import {model, Schema} from 'mongoose';
import {TwoFA} from '../../types/2FA';

const TwoFASchema = new Schema<TwoFA>({
  // TODO: add userId (Number, required, unique)
  userId: {type: Number, required: true, unique: true},
  // TODO: add email (String, required, unique)
  email: {type: String, required: true, unique: true},
  // TODO: add twoFactorSecret (String, required)
  twoFactorSecret: {type: String, required: true},
  // TODO: add twoFactorEnabled (Boolean, default: false)
  twoFactorEnabled: {type: Boolean, default: false},
});

export default model<TwoFA>('TwoFA', TwoFASchema);
