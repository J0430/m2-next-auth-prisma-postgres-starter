// AST-backed fail-closed inventory for account creation and activation writes.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve } from "node:path";
import ts from "typescript";

type SourceOverrides = Readonly<Record<string, string>>;

export type CreationSurfaceInventory = Readonly<{
  entries: readonly string[];
  activeStatusDefaults: readonly string[];
  missingElevationProof: readonly string[];
  productionBootstrapImports: readonly string[];
}>;

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);

function sourceFiles(root: string): string[] {
  const results: string[] = [];
  const visit = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const absolute = resolve(directory, name);
      const stat = statSync(absolute);
      if (stat.isDirectory()) visit(absolute);
      else if (SOURCE_EXTENSIONS.has(name.slice(name.lastIndexOf(".")))) {
        results.push(relative(root, absolute).replaceAll("\\", "/"));
      }
    }
  };
  for (const directory of ["prisma", "src", "app"]) {
    try { visit(resolve(root, directory)); } catch (error: unknown) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    }
  }
  return results;
}

function propertyName(node: ts.Node): string | null {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node)) return node.text;
  return null;
}

function memberName(node: ts.Expression): string | null {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node) && node.argumentExpression) {
    return propertyName(node.argumentExpression);
  }
  return null;
}

function memberOwner(node: ts.Expression): ts.Expression | null {
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return node.expression;
  return null;
}

function nearestInitializer(source: ts.SourceFile, name: string, before: number): ts.Expression | null {
  const matches: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node): void => {
    if (node.getStart(source) >= before) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer) {
      matches.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  const best = matches.sort((left, right) => right.getStart(source) - left.getStart(source))[0];
  return best?.initializer ?? null;
}

function objectProperty(source: ts.SourceFile, object: ts.ObjectLiteralExpression, name: string): ts.Expression | null {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property) && propertyName(property.name) === name) return property.initializer;
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === name) {
      return nearestInitializer(source, name, property.getStart(source));
    }
  }
  return null;
}

function resolveExpression(source: ts.SourceFile, expression: ts.Expression, before: number): ts.Expression {
  if (ts.isIdentifier(expression)) {
    return nearestInitializer(source, expression.text, before) ?? expression;
  }
  return expression;
}

function expressionIsActive(
  source: ts.SourceFile,
  expression: ts.Expression,
  before: number,
  depth = 0,
): boolean {
  if (depth > 8) return false;
  const resolved = resolveExpression(source, expression, before);
  if (ts.isStringLiteral(resolved)) return resolved.text === "ACTIVE";
  if (ts.isPropertyAccessExpression(resolved) || ts.isElementAccessExpression(resolved)) {
    const name = memberName(resolved);
    if (name === "ACTIVE") return true;
    const owner = memberOwner(resolved);
    if (!name || !owner) return false;
    const object = resolveExpression(source, owner, before);
    return ts.isObjectLiteralExpression(object) && Boolean(
      objectProperty(source, object, name) &&
      expressionIsActive(source, objectProperty(source, object, name) ?? owner, before, depth + 1),
    );
  }
  return ts.isIdentifier(resolved) && resolved.text === "ACTIVE";
}

function objectHasActiveStatus(
  source: ts.SourceFile,
  object: ts.ObjectLiteralExpression,
  before: number,
  depth = 0,
): boolean {
  if (depth > 8) return false;
  const status = objectProperty(source, object, "status");
  if (status && expressionIsActive(source, status, before, depth + 1)) return true;
  return object.properties.some(property => {
    if (!ts.isSpreadAssignment(property)) return false;
    const spread = resolveExpression(source, property.expression, before);
    return ts.isObjectLiteralExpression(spread) && objectHasActiveStatus(source, spread, before, depth + 1);
  });
}

function callObjectArgument(source: ts.SourceFile, node: ts.CallExpression): ts.ObjectLiteralExpression | null {
  const argument = node.arguments[0];
  if (!argument) return null;
  const resolved = resolveExpression(source, argument, node.getStart(source));
  return ts.isObjectLiteralExpression(resolved) ? resolved : null;
}

function activeInMutationData(source: ts.SourceFile, node: ts.CallExpression): boolean {
  const input = callObjectArgument(source, node);
  if (!input) return false;
  const data = objectProperty(source, input, "data");
  if (!data) return false;
  const resolvedData = resolveExpression(source, data, node.getStart(source));
  if (!ts.isObjectLiteralExpression(resolvedData)) return false;
  return objectHasActiveStatus(source, resolvedData, node.getStart(source));
}

function destructuredUserCall(
  source: ts.SourceFile,
  node: ts.CallExpression,
): { method: string; client: ts.Expression } | null {
  if (!ts.isIdentifier(node.expression)) return null;
  const callName = node.expression.text;
  const matches: Array<{ method: string; client: ts.Expression; start: number }> = [];
  const visit = (candidate: ts.Node): void => {
    if (candidate.getStart(source) >= node.getStart(source)) return;
    if (ts.isVariableDeclaration(candidate) && ts.isObjectBindingPattern(candidate.name) && candidate.initializer &&
      memberName(candidate.initializer) === "user") {
      const client = memberOwner(candidate.initializer);
      for (const element of candidate.name.elements) {
        if (element.name.getText(source) !== callName || !client) continue;
        const method = element.propertyName ? propertyName(element.propertyName) : element.name.getText(source);
        if (method) matches.push({ method, client, start: candidate.getStart(source) });
      }
    }
    ts.forEachChild(candidate, visit);
  };
  visit(source);
  const match = matches.sort((left, right) => right.start - left.start)[0];
  return match ? { method: match.method, client: match.client } : null;
}

function userCall(source: ts.SourceFile, node: ts.CallExpression): { method: string; client: ts.Expression } | null {
  const method = memberName(node.expression);
  const owner = memberOwner(node.expression);
  if (!method || !owner || memberName(owner) !== "user") return destructuredUserCall(source, node);
  const client = memberOwner(owner);
  return client ? { method, client } : null;
}

function callKind(source: ts.SourceFile, node: ts.CallExpression): string | null {
  const target = userCall(source, node);
  if (!target) return null;
  if (target.method === "create" || target.method === "upsert") return `user.${target.method}`;
  if ((target.method === "update" || target.method === "updateMany") && activeInMutationData(source, node)) {
    return `user.${target.method}`;
  }
  return null;
}

function literalStatus(source: ts.SourceFile, node: ts.CallExpression): "ACTIVE" | "INACTIVE" {
  const target = userCall(source, node);
  if (!target) return "INACTIVE";
  if (target.method === "update" || target.method === "updateMany") {
    return activeInMutationData(source, node) ? "ACTIVE" : "INACTIVE";
  }
  const input = callObjectArgument(source, node);
  if (!input) return "INACTIVE";
  for (const field of ["data", "create"] as const) {
    const candidate = field === "data" ? objectProperty(source, input, field) : objectProperty(source, input, field);
    const object = candidate ? resolveExpression(source, candidate, node.getStart(source)) : input;
    if (ts.isObjectLiteralExpression(object)) {
      if (objectHasActiveStatus(source, object, node.getStart(source))) return "ACTIVE";
    }
  }
  return "INACTIVE";
}

function enclosingTransaction(node: ts.CallExpression): { callback: ts.SignatureDeclaration; tx: string } | null {
  let callback: ts.Node | undefined = node.parent;
  while (callback && !ts.isFunctionLike(callback)) callback = callback.parent;
  if (!callback || !ts.isFunctionLike(callback) || !callback.parent || !ts.isCallExpression(callback.parent)) return null;
  const transactionCall = callback.parent;
  if (memberName(transactionCall.expression) !== "$transaction") return null;
  const parameter = callback.parameters[0];
  return parameter && ts.isIdentifier(parameter.name) ? { callback, tx: parameter.name.text } : null;
}

function rootIdentifier(expression: ts.Expression): string | null {
  let current = expression;
  while (memberOwner(current)) current = memberOwner(current) ?? current;
  return ts.isIdentifier(current) ? current.text : null;
}

function callResultName(node: ts.CallExpression): string | null {
  let current: ts.Node = node;
  if (ts.isAwaitExpression(node.parent)) current = node.parent;
  return ts.isVariableDeclaration(current.parent) && ts.isIdentifier(current.parent.name)
    ? current.parent.name.text
    : null;
}

function contextUsesTransaction(
  source: ts.SourceFile,
  argument: ts.Expression,
  transactionName: string,
  before: number,
): boolean {
  const context = resolveExpression(source, argument, before);
  if (!ts.isObjectLiteralExpression(context)) return false;
  for (const property of context.properties) {
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === "tx") {
      return property.name.text === transactionName;
    }
    if (ts.isPropertyAssignment(property) && propertyName(property.name) === "tx") {
      const resolved = resolveExpression(source, property.initializer, before);
      return ts.isIdentifier(resolved) && resolved.text === transactionName;
    }
  }
  return false;
}

function hasTransactionalElevationProof(source: ts.SourceFile, creation: ts.CallExpression): boolean {
  const transaction = enclosingTransaction(creation);
  const target = userCall(source, creation);
  if (!transaction || !target || rootIdentifier(target.client) !== transaction.tx) return false;
  const creationStart = creation.getStart(source);
  const createdName = callResultName(creation);
  let grantName: string | null = null;
  let elevationBeforeCreate = false;
  let associatedAuditAfterCreate = false;
  const visit = (candidate: ts.Node): void => {
    if (candidate !== transaction.callback && ts.isFunctionLike(candidate)) return;
    if (ts.isCallExpression(candidate) && candidate !== creation) {
      if (ts.isIdentifier(candidate.expression) && candidate.expression.text === "requireAdminElevation") {
        const contextArgument = candidate.arguments[0];
        const capability = candidate.arguments[1];
        const sameTx = Boolean(contextArgument && contextUsesTransaction(
          source, contextArgument, transaction.tx, candidate.getStart(source),
        ));
        if (candidate.getStart(source) < creationStart && sameTx && capability && ts.isStringLiteral(capability) &&
          capability.text === "admin:user:create") {
          elevationBeforeCreate = true;
          grantName = callResultName(candidate);
        }
      }
      const owner = memberOwner(candidate.expression);
      if (memberName(candidate.expression) === "create" && owner && memberName(owner) === "auditEvent" &&
        rootIdentifier(memberOwner(owner) ?? owner) === transaction.tx && candidate.getStart(source) > creationStart) {
        const text = candidate.getText(source);
        associatedAuditAfterCreate = Boolean(createdName && grantName && text.includes(`${createdName}.id`) &&
          text.includes(`${grantName}.actorId`) && text.includes("admin.user.created"));
      }
    }
    ts.forEachChild(candidate, visit);
  };
  visit(transaction.callback);
  return elevationBeforeCreate && associatedAuditAfterCreate;
}

function adapterEntry(source: ts.SourceFile, node: ts.Node): { line: number; denied: boolean } | null {
  let name: string | null = null;
  let body = "";
  if (ts.isPropertyAssignment(node)) { name = propertyName(node.name); body = node.initializer.getText(source); }
  else if (ts.isMethodDeclaration(node)) { name = propertyName(node.name); body = node.getText(source); }
  else if (ts.isShorthandPropertyAssignment(node)) { name = node.name.text; body = node.name.text; }
  if (name !== "createUser") return null;
  if (ts.isShorthandPropertyAssignment(node)) {
    body = nearestInitializer(source, name, node.getStart(source))?.getText(source) ?? body;
    const declaration = source.statements.find(statement =>
      ts.isFunctionDeclaration(statement) && statement.name?.text === name &&
      statement.getStart(source) < node.getStart(source));
    if (declaration) body = declaration.getText(source);
  }
  return { line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1, denied: /deny|throw/.test(body) };
}

function scanFile(path: string, sourceText: string): { activeDefaults: string[]; entries: string[]; missingProof: string[] } {
  const source = ts.createSourceFile(path, sourceText, ts.ScriptTarget.Latest, true);
  const entries: string[] = [];
  const activeDefaults: string[] = [];
  const missingProof: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const kind = callKind(source, node);
      if (kind) {
        const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        const entry = `${path}:${line}:${kind}:${literalStatus(source, node)}`;
        entries.push(entry);
        const productionCreation = (path.startsWith("src/") || path.startsWith("app/")) &&
          (kind === "user.create" || kind === "user.upsert");
        const trustedPath = productionCreation &&
          path !== "src/features/auth/server/registration/registerWithInvite.ts" &&
          path !== "src/features/auth/server/registration/bootstrapCreateActiveUser.ts";
        if (trustedPath && !hasTransactionalElevationProof(source, node)) missingProof.push(entry);
      }
      if (memberName(node.expression) === "createUser") {
        const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        const entry = `${path}:${line}:adapter.createUser:CALL`;
        entries.push(entry);
        missingProof.push(entry);
      }
    }
    if (ts.isParameter(node) && node.initializer && expressionIsActive(source, node.initializer, node.getStart(source))) {
      activeDefaults.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`);
    }
    if (ts.isBindingElement(node) && node.initializer && expressionIsActive(source, node.initializer, node.getStart(source))) {
      activeDefaults.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`);
    }
    const adapter = adapterEntry(source, node);
    if (adapter) {
      const entry = `${path}:${adapter.line}:adapter.createUser:${adapter.denied ? "DENY" : "CREATE"}`;
      entries.push(entry);
      if (!adapter.denied) missingProof.push(entry);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return { activeDefaults, entries, missingProof };
}

function importsBootstrap(source: ts.SourceFile): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier) && node.moduleSpecifier.text.includes("bootstrapCreateActiveUser")) found = true;
    if (ts.isCallExpression(node) && ((node.expression.kind === ts.SyntaxKind.ImportKeyword) ||
      (ts.isIdentifier(node.expression) && node.expression.text === "require"))) {
      const target = node.arguments[0];
      if (target && ts.isStringLiteral(target) && target.text.includes("bootstrapCreateActiveUser")) found = true;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

export function analyzeCreationSources(root: string, overrides: SourceOverrides = {}): CreationSurfaceInventory {
  const paths = [...new Set([...sourceFiles(root), ...Object.keys(overrides)])].sort();
  const entries: string[] = [];
  const activeStatusDefaults: string[] = [];
  const missingElevationProof: string[] = [];
  const productionBootstrapImports: string[] = [];
  for (const path of paths) {
    const sourceText = overrides[path] ?? readFileSync(resolve(root, path), "utf8");
    const source = ts.createSourceFile(path, sourceText, ts.ScriptTarget.Latest, true);
    const result = scanFile(path, sourceText);
    entries.push(...result.entries);
    activeStatusDefaults.push(...result.activeDefaults);
    missingElevationProof.push(...result.missingProof);
    if ((path.startsWith("src/") || path.startsWith("app/")) && importsBootstrap(source)) {
      productionBootstrapImports.push(path);
    }
  }
  return { entries: entries.sort(), activeStatusDefaults: activeStatusDefaults.sort(),
    missingElevationProof: missingElevationProof.sort(), productionBootstrapImports: productionBootstrapImports.sort() };
}

export function assertCreationInventory(inventory: CreationSurfaceInventory, allowlist: readonly string[]): void {
  const reviewed = new Set(allowlist);
  const actual = new Set(inventory.entries);
  const unreviewed = inventory.entries.filter(entry => !reviewed.has(entry));
  if (unreviewed.length > 0) throw new Error(`Unreviewed creation surface: ${unreviewed.join(", ")}`);
  const stale = allowlist.filter(entry => !actual.has(entry));
  if (stale.length > 0) throw new Error(`Stale creation allowlist: ${stale.join(", ")}`);
  const activeCreationBypasses = inventory.entries.filter(entry =>
    (entry.includes(":user.create:ACTIVE") || entry.includes(":user.upsert:ACTIVE")) &&
    !entry.startsWith("src/features/auth/server/registration/bootstrapCreateActiveUser.ts:"));
  if (activeCreationBypasses.length > 0) throw new Error(
    `ACTIVE creation outside bootstrap exemption: ${activeCreationBypasses.join(", ")}`,
  );
  if (inventory.missingElevationProof.length > 0) throw new Error(
    `Trusted creation lacks elevation proof: ${inventory.missingElevationProof.join(", ")}`,
  );
  if (inventory.activeStatusDefaults.length > 0) throw new Error(
    `Creation helper defaults status to ACTIVE: ${inventory.activeStatusDefaults.join(", ")}`,
  );
  if (inventory.productionBootstrapImports.length > 0) throw new Error(
    `Production bootstrap import: ${inventory.productionBootstrapImports.join(", ")}`,
  );
}
