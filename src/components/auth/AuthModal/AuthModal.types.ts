export type AuthModalProps = {
  isOpen: boolean;
  onCloseAction: () => void;
  /** Called after successful signup/signin. Falls back to onCloseAction. */
  onSuccessAction?: () => void;
  initialTab?: 'login' | 'signup';
};