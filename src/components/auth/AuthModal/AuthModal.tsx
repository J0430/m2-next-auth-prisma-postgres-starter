'use client';
import {
  Modal, ModalOverlay, ModalContent, ModalBody, ModalCloseButton,
} from '@chakra-ui/react';
import type { AuthModalProps } from './AuthModal.types';
import styles from './AuthModal.module.scss';
import AuthLayout from '@/components/auth/AuthLayout';

export default function AuthModal({
  isOpen,
  onCloseAction,
  onSuccessAction,
  initialTab,
}: AuthModalProps) {
  return (
    <Modal isOpen={isOpen} onClose={onCloseAction} size="5xl" isCentered>
      <ModalOverlay />
      <ModalContent className={styles.modal} p={0} borderRadius="xl" boxShadow="xl" overflow="hidden">
        <ModalCloseButton zIndex={2} />
        <ModalBody p={0}>
          <AuthLayout
            onSuccessAction={onSuccessAction ?? onCloseAction}
            initialTab={initialTab}
          />
        </ModalBody>
      </ModalContent>
    </Modal>
  );
}