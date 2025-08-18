import { Transporter } from 'nodemailer';
import { Logger } from 'winston';

export class EmailService {
  constructor(
    private transporter: Transporter,
    private logger: Logger
  ) {}

  async sendTemporaryPasswordEmail(email: string, tempPassword: string): Promise<void> {
    // const mailOptions = {
    //   from: process.env.EMAIL_USER,
    //   to: email,
    //   subject: 'Your Temporary Password',
    //   text: `Your temporary password is: ${tempPassword}\nPlease change it after logging in.`,
    //   html: `<p>Your temporary password is: <strong>${tempPassword}</strong></p><p>Please change it after logging in.</p>`,
    // };

    // try {
    //   await this.transporter.sendMail(mailOptions);
    //   this.logger.info(`Temporary password email sent to ${email}`);
    // } catch (error) {
    //   this.logger.error('Error sending temporary password email:', error);
    //   throw new Error('Failed to send temporary password email');
    // }
    console.log(
      `Sending temporary password to ${email}: ${tempPassword}`
    );
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Email Verification',
      text: `Please verify your email by clicking the link: ${process.env.CLIENT_URL}/verify-email?token=${token}`
    };

    try {
      await this.transporter.sendMail(mailOptions);
      this.logger.info(`Verification email sent to ${email}`);
    } catch (error) {
      this.logger.error('Error sending verification email:', error);
      throw new Error('Failed to send verification email');
    }
  }
}
