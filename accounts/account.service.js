const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');
const Account = db.Account;

module.exports = {
    authenticate,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password }) {
    const account = await Account.findOne({ email, isVerified: true });
    if (account && bcrypt.compareSync(password, account.passwordHash)) {
        // return basic details and auth token
        const token = jwt.sign({ sub: account.id, id: account.id }, config.secret);
        return { ...basicDetails(account), token };
    }
}

async function register(params, origin) {
    // validate
    if (await Account.findOne({ email: params.email })) {
        // send already registered error in email to prevent account enumeration
        return sendAlreadyRegisteredEmail(params.email, origin);
    }

    // create account object
    const account = new Account(params);

    // first registered account is an admin
    const isFirstAccount = (await Account.countDocuments({})) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = generateToken();
    account.isVerified = false;

    // hash password
    if (params.password) {
        account.passwordHash = hash(params.password);
    }

    // save account
    await account.save();

    // send email
    sendVerificationEmail(account, origin);
}

async function verifyEmail({ token }) {
    const account = await Account.findOne({ verificationToken: token });
    
    if (!account) throw 'Verification failed';
    
    account.isVerified = true;
    await account.save();
}

async function forgotPassword({ email }, origin) {
    const account = await Account.findOne({ email });
    
    // always return ok response to prevent email enumeration
    if (!account) return;
    
    // create reset token that expires after 24 hours
    account.resetToken = generateToken();
    account.resetTokenExpiry = new Date(Date.now() + 24*60*60*1000).toISOString();
    account.save();

    // send email
    sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }) {
    const account = await Account.findOne({ 
        resetToken: token,
        resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!account) throw 'Invalid token';
}

async function resetPassword({ token, password }) {
    const account = await Account.findOne({ 
        resetToken: token,
        resetTokenExpiry: { $gt: new Date() }
    });
    
    if (!account) throw 'Invalid token';
    
    // update password and remove reset token
    account.passwordHash = hash(password);
    account.isVerified = true;
    account.resetToken = undefined;
    account.resetTokenExpiry = undefined;
    await account.save();
}

async function getAll() {
    const accounts = await Account.find();
    return accounts.map(x => basicDetails(x));
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params) {
    // validate
    if (await Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already registered';
    }

    const account = new Account(params);
    account.isVerified = true;

    // hash password
    if (params.password) {
        account.passwordHash = hash(params.password);
    }

    // save account
    await account.save();

    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount(id);

    // validate
    if (account.email !== params.email && await Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" is already taken';
    }

    // hash password if it was entered
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copy params to account and save
    Object.assign(account, params);
    account.dateUpdated = Date.now();
    await account.save();

    return basicDetails(account);
}

async function _delete(id) {
    const account = await getAccount(id);
    await account.remove();
}

// helper functions

async function getAccount(id) {
    if (!db.isValidId(id)) throw 'Account not found';
    const account = await Account.findById(id);
    if (!account) throw 'Account not found';
    return account;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateToken() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, dateCreated, dateUpdated } = account;
    return { id, title, firstName, lastName, email, role, dateCreated, dateUpdated };
}

function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Please click the below link to verify your email address:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to verify your email address with the <code>/account/verify-email</code> api route:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }

    sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Verify Email',
        html: `<h4>Verify Email</h4>
               <p>Thanks for registering!</p>
               ${message}`
    });
}

function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    if (origin) {
        message = `<p>If you don't know your password please visit the <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>If you don't know your password you can reset it via the <code>/account/forgot-password</code> api route.</p>`;
    }

    sendEmail({
        to: email,
        subject: 'Sign-up Verification API - Email Already Registered',
        html: `<h4>Email Already Registered</h4>
               <p>Your email <strong>${email}</strong> is already registered.</p>
               ${message}`
    });
}

function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken}`;
        message = `<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Please use the below token to reset your password with the <code>/account/reset-password</code> api route:</p>
                   <p><code>${account.resetToken}</code></p>`;
    }

    sendEmail({
        to: account.email,
        subject: 'Sign-up Verification API - Reset Password',
        html: `<h4>Reset Password Email</h4>
               ${message}`
    });
}