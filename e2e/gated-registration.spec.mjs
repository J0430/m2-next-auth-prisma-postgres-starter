// Deferred TASK-028 browser proof for invitation registration UX and CSP behavior.
import { expect, test } from "@playwright/test";

const RAW_TOKEN = "A".repeat(43);
const OPAQUE_HANDLE = "H".repeat(43);

test("history strips the invite fragment before registration navigation", async ({ page }) => {
  const thirdPartyBeforeExchange = [];
  let exchangeStarted = false;
  page.on("request", (request) => {
    if (request.url().includes("/api/invitations/exchange")) exchangeStarted = true;
    const url = new URL(request.url());
    if (!exchangeStarted && url.origin !== new URL(page.url() || "http://localhost").origin) {
      thirdPartyBeforeExchange.push(request.url());
    }
  });
  await page.route("**/api/invitations/exchange", (route) => route.fulfill({
    status: 303,
    headers: {
      location: "/register",
      "set-cookie": `registration_session=${OPAQUE_HANDLE}; HttpOnly; Secure; SameSite=Strict; Path=/register; Max-Age=600`,
    },
    body: "",
  }));
  await page.goto(`/invite#token=${RAW_TOKEN}`);
  await expect(page).toHaveURL(/\/register$/u);
  expect(page.url()).not.toContain("#");
  expect(thirdPartyBeforeExchange).toEqual([]);
  expect(await page.content()).not.toContain(RAW_TOKEN);
  expect(await page.locator(`input[value="${RAW_TOKEN}"]`).count()).toBe(0);
  expect(await page.evaluate(() => ({
    local: Object.values(localStorage),
    session: Object.values(sessionStorage),
    cookie: document.cookie,
    href: location.href,
    hash: location.hash,
  }))).toEqual({ local: [], session: [], cookie: "", href: expect.not.stringContaining(RAW_TOKEN), hash: "" });
  expect(JSON.stringify(await page.context().cookies())).not.toContain(RAW_TOKEN);
});

test("Profile A protects invite while Profile B permits only Turnstile", async ({ page }) => {
  const invite = await page.goto("/invite");
  const firstInviteCsp = invite?.headers()["content-security-policy"] ?? "";
  expect(firstInviteCsp).toMatch(/script-src 'self' 'nonce-[^']+'(?:;|$)/u);
  expect(firstInviteCsp).toContain("connect-src 'self'");
  expect(firstInviteCsp).toContain("object-src 'none'");
  expect(firstInviteCsp).toContain("base-uri 'self'");
  expect(firstInviteCsp).toContain("frame-ancestors 'none'");
  expect(firstInviteCsp).not.toContain("challenges.cloudflare.com");
  expect(firstInviteCsp).not.toContain("'unsafe-inline'");
  expect(firstInviteCsp).not.toContain("'unsafe-eval'");
  const inviteNonce = firstInviteCsp.match(/'nonce-([^']+)'/u)?.[1];
  expect(inviteNonce).toBeTruthy();
  await expect(page.locator(`script[nonce="${inviteNonce}"]`).first()).toBeAttached();

  const secondInvite = await page.goto("/invite");
  const secondInviteCsp = secondInvite?.headers()["content-security-policy"] ?? "";
  expect(secondInviteCsp).not.toBe(firstInviteCsp);

  const register = await page.goto("/register");
  const registerCsp = register?.headers()["content-security-policy"] ?? "";
  expect(registerCsp).toMatch(/script-src 'self' 'nonce-[^']+' https:\/\/challenges\.cloudflare\.com(?:;|$)/u);
  expect(registerCsp).toContain("frame-src https://challenges.cloudflare.com");
  expect(registerCsp).toContain("connect-src 'self' https://challenges.cloudflare.com");
  expect(registerCsp).toContain("object-src 'none'");
  expect(registerCsp).toContain("base-uri 'self'");
  expect(registerCsp).toContain("frame-ancestors 'none'");
  expect(registerCsp).not.toContain("'unsafe-eval'");
  expect(registerCsp).not.toContain("'unsafe-inline'");
  const registerNonce = registerCsp.match(/'nonce-([^']+)'/u)?.[1];
  expect(registerNonce).toBeTruthy();
  expect(registerNonce).not.toBe(inviteNonce);
  await expect(page.locator(`script[nonce="${registerNonce}"]`).first()).toBeAttached();
});

test("registration supports keyboard navigation and responsive layout", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/register");
  await expect(page.getByRole("heading", { name: "Create your invited account" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("First name")).toBeFocused();
  await page.getByLabel("Email").fill("person@example.com");
  await expect(page.locator("main")).toHaveCSS("max-width", "576px");
  // responsive and keyboard evidence is completed in TASK-028 across viewports.
});

test.describe("no-JS invitation fallback", () => {
  test.use({ javaScriptEnabled: false });

  test("transmits nothing and exposes only generic copy", async ({ page }) => {
    let exchangeRequests = 0;
    page.on("request", (request) => {
      if (request.url().includes("/api/invitations/exchange")) exchangeRequests += 1;
    });
    await page.goto(`/invite#token=${RAW_TOKEN}`);
    await expect(page.getByText("JavaScript is required to accept this invitation.")).toBeVisible();
    expect(exchangeRequests).toBe(0);
    expect(await page.content()).not.toContain(RAW_TOKEN);
  });
});
