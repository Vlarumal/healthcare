export const sendTemporaryPasswordEmail = jest.fn().mockImplementation((email: string, _password: string) => {
  console.log(`Mock: Sending temporary password to ${email}`);
  return Promise.resolve();
});

export const sendPasswordResetEmail = jest.fn().mockResolvedValue(undefined);
export const sendAccountActivationEmail = jest.fn().mockResolvedValue(undefined);