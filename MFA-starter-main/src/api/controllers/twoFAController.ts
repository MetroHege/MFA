import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {TokenContent, User, UserWithLevel} from '@sharedTypes/DBTypes';
import fetchData from '../../utils/fetchData';
import OTPAuth from 'otpauth';
import twoFAModel from '../models/twoFAModel';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';
// TODO: Import necessary types and models

// Define setupTwoFA function
const setupTwoFA = async (
  req: Request<{}, {}, User>,
  res: Response<{qrCodeUrl: String}>,
  next: NextFunction,
) => {
  try {
    // Register user to AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const UserResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    //console.log('UserResponse:', UserResponse);

    // Generate a new 2FA secret
    const secret = new OTPAuth.Secret();

    // Create the TOTP instance
    const totp = new OTPAuth.TOTP({
      issuer: 'MFAtesti',
      label: UserResponse.user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: secret,
    });

    console.log('totp:', totp.toString());

    // Store or update the 2FA data in the database
    await twoFAModel.create({
      email: UserResponse.user.email,
      userId: UserResponse.user.user_id,
      twoFactorEnabled: true,
      twoFactorSecret: secret.base32,
    });

    // Generate a QR code and send it in the response
    const imageUrl = await QRCode.toDataURL(totp.toString());

    res.json({qrCodeUrl: imageUrl});
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Define verifyTwoFA function
const verifyTwoFA = async (
  req: Request<{}, {}, {email: string; code: string}>,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  const {email, code} = req.body;

  try {
    // Retrieve 2FA data from the database
    const twoFactorData = await twoFAModel.findOne({email: email});
    if (!twoFactorData || !twoFactorData.twoFactorEnabled) {
      next(new CustomError('2FA is not enabled for this user', 400));
      return;
    }

    console.log('twoFactorData:', twoFactorData);

    // Validate the 2FA code
    const totp = new OTPAuth.TOTP({
      issuer: 'MFAtesti',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(twoFactorData.twoFactorSecret),
    });

    const isValid = totp.validate({
      token: code,
      window: 1,
    });

    if (!isValid) {
      next(new CustomError('Invalid 2FA code', 400));
      return;
    }

    // If valid, get the user from AUTH API
    const UserResponse = await fetchData<UserWithLevel>(
      process.env.AUTH_URL + '/api/v1/users/' + twoFactorData.userId,
    );

    if (!UserResponse) {
      next(new CustomError('User not found', 404));
      return;
    }

    // Create and return a JWT token
    const tokenContent: TokenContent = {
      user_id: twoFactorData.userId,
      level_name: UserResponse.level_name,
    };

    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined');
    }

    const token = jwt.sign(tokenContent, process.env.JWT_SECRET);
    const loginResponse: LoginResponse = {
      user: UserResponse,
      token: token,
      message: 'Login successful',
    };

    res.json(loginResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
