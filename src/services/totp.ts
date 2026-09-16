import crypto from 'crypto';

/**
 * TOTP (Time-based One-Time Password) service
 * Implements RFC 6238 standard
 */
export class TOTPService {
  private static readonly TIME_STEP = 30; // seconds
  private static readonly DIGITS = 6;
  private static readonly ALGORITHM = 'sha1';

  /**
   * Generates a secret for TOTP
   */
  static generateSecret(): string {
    return crypto.randomBytes(20).toString('base64');
  }

  /**
   * Generates a TOTP code from a secret
   */
  static generateCode(secret: string, timestamp?: number): string {
    const time = Math.floor((timestamp || Date.now()) / 1000 / this.TIME_STEP);
    const key = Buffer.from(secret.replace(/\s/g, ''), 'base64');
    const counter = Buffer.alloc(8);

    for (let i = 7; i >= 0; i--) {
      counter[i] = time & 0xff;
      time = time >> 8;
    }

    const hmac = crypto.createHmac(this.ALGORITHM, key);
    hmac.update(counter);
    const digest = hmac.digest();

    const offset = digest[digest.length - 1] & 0xf;
    const code =
      (digest[offset] & 0x7f) << 24 |
      (digest[offset + 1] & 0xff) << 16 |
      (digest[offset + 2] & 0xff) << 8 |
      (digest[offset + 3] & 0xff);

    return (code % Math.pow(10, this.DIGITS)).toString().padStart(this.DIGITS, '0');
  }

  /**
   * Verifies a TOTP code with a time window
   */
  static verifyCode(secret: string, code: string, window: number = 1): boolean {
    const timestamp = Date.now();
    const codes = [];

    // Check current time and surrounding times for clock skew
    for (let i = -window; i <= window; i++) {
      const checkTime = timestamp + i * this.TIME_STEP * 1000;
      codes.push(this.generateCode(secret, checkTime));
    }

    return codes.includes(code);
  }

  /**
   * Generates a provisioning URI for QR code generation
   */
  static getProvisioningUri(secret: string, accountName: string, issuer: string = 'SecureAuth'): string {
    const encodedAccount = encodeURIComponent(accountName);
    const encodedIssuer = encodeURIComponent(issuer);
    return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}`;
  }
}
