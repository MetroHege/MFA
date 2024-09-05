import { Button } from "./ui/button";

const Setup2FA = (props: { qrCodeUrl: string; switchForm: () => void }) => {
  const { qrCodeUrl, switchForm } = props;
  return (
    <div className="p-4">
      <img src={qrCodeUrl} alt="Authenticator QR code" />
      <Button onClick={switchForm}>Press here when QR code is scanned</Button>
    </div>
  );
};

export default Setup2FA;
