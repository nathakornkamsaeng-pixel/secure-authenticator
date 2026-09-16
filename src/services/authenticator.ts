import { EncryptionService } from './encryption';
import { TOTPService } from './totp';
import { CookieService, AuthenticationPayload } from './cookie';

export interface SetupCredentials {
  password: string;
  totpSecret?: string;
}

export interface AuthenticateRequest {
  password: string;
  totpCode?: string;
}

/**
 * Main authenticator service orchestrating password, TOTP, and cookies
 */
export class AuthenticatorService {
  /**
   * Sets up a new user with password and optional TOTP
   */
  static setupUser(userId: string, username: string, credentials: SetupCredentials): AuthenticationPayload {
    const passwordHash = EncryptionService.hashPassword(credentials.password);
    const totpSecret = credentials.totpSecret || TOTPService.generateSecret();

    return {
      userId,
      username,
      passwordHash,
      totpSecret,
      createdAt: Date.now(),
    };
  }

  /**
   * Authenticates user with password and optional TOTP
   */
  static authenticate(
    storedPayload: AuthenticationPayload,
    request: AuthenticateRequest
  ): boolean {
    // Verify password
    try {
      if (!EncryptionService.verifyPassword(request.password, storedPayload.passwordHash)) {
        return false;
      }
    } catch (error) {
      console.error('Password verification failed:', error);
      return false;
    }

    // Verify TOTP if provided
    if (request.totpCode) {
      if (!TOTPService.verifyCode(storedPayload.totpSecret, request.totpCode)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Creates an authenticated session cookie
   */
  static createSessionCookie(
    payload: AuthenticationPayload,
    encryptionPassword: string
  ): string {
    return CookieService.createAuthCookie(payload, encryptionPassword);
  }

  /**
   * Validates a session cookie
   */
  static validateSessionCookie(
    cookieString: string,
    encryptionPassword: string
  ): AuthenticationPayload | null {
    if (!CookieService.isCookieValid(cookieString, encryptionPassword)) {
      return null;
    }

    return CookieService.parseAuthCookie(cookieString, encryptionPassword);
  }

  /**
   * Gets TOTP provisioning URI for QR code
   */
  static getTOTPProvisioningUri(username: string, totpSecret: string, issuer?: string): string {
    return TOTPService.getProvisioningUri(totpSecret, username, issuer);
  }

  /**
   * Generates a new TOTP secret
   */
  static generateTOTPSecret(): string {
    return TOTPService.generateSecret();
  }

  /**
   * Verifies TOTP code
   */
  static verifyTOTPCode(totpSecret: string, code: string): boolean {
    return TOTPService.verifyCode(totpSecret, code);
  }

  /**
   * Exports payload for storage (e.g., database)
   */
  static exportPayload(payload: AuthenticationPayload): string {
    return JSON.stringify(payload);
  }

  /**
   * Imports payload from storage
   */
  static importPayload(payloadString: string): AuthenticationPayload {
    return JSON.parse(payloadString) as AuthenticationPayload;
  }
}
