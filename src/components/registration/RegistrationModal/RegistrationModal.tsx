'use client';
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalBody,
  ModalCloseButton,
} from '@chakra-ui/react';
import type { RegistrationModalProps } from './RegistrationModal.types';
import styles from './RegistrationModal.module.scss';
import RegistrationLayout from '@/components/registration/RegistrationLayout';

export default function RegistrationModal({
  isOpen,
  onClose,
  onSuccess,
}: RegistrationModalProps) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} size="5xl" isCentered>
      <ModalOverlay />
      <ModalContent
        className={styles.modal}
        p={0}
        borderRadius="xl"
        boxShadow="xl"
        overflow="hidden"
      >
        <ModalCloseButton zIndex={2} />
        <ModalBody p={0}>
          <RegistrationLayout onSuccess={onSuccess ?? onClose} />
        </ModalBody>
      </ModalContent>
    </Modal>
  );
}
