export type RegistrationModalProps = {
  isOpen: boolean;
  onClose: () => void;
  /** Called after successful signup. Falls back to onClose in component. */
  onSuccess?: () => void;
};
