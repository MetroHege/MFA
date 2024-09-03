import express from 'express';
import {setupTwoFA} from '../controllers/twoFAController';

const router = express.Router();

//router.route('/verify').post(verifyTwoFA);
router.route('/setup').post(setupTwoFA);

export default router;
