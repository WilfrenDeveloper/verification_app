const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const sendEmail = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken');

const getAll = catchError(async (req, res) => {
    const results = await User.findAll();
    return res.json(results);
});

const create = catchError(async (req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body;
    const encriptedPassword = await bcrypt.hash(password, 10);
    const result = await User.create({
        email,
        password: encriptedPassword,
        firstName, lastName, country, image
    });

    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/verify_email/${code}`
    await EmailCode.create({
        code,
        userId: result.id
    })

    await sendEmail({
        to: email,
        subject: 'Verifiqued email for User App',
        html: `
            <h1>Hello ${firstName} ${lastName}</h1>
            <h3>Thanks for sing up in user app</h3>
            <br>
            <p>Verification link</p>
            <b>${link}</b>
        `
    });
    return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.findByPk(id);
    if (!result) return res.sendStatus(404);
    return res.json(result);
});

const remove = catchError(async (req, res) => {
    const { id } = req.params;
    await User.destroy({ where: { id } });
    return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
    const { id } = req.params;
    const result = await User.update(
        req.body,
        { where: { id }, returning: true }
    );
    if (result[0] === 0) return res.sendStatus(404);
    return res.json(result[1][0]);
});

const verifyCode = catchError(async (req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({ where: { code: code } });
    if (!emailCode) return res.status(401).json({ messaje: "error de código" })
    /*
    const user = await User.findByPk(emailCode.userId);
    user.isVerify = true;
    await user.save();
    */
    const user = await User.update(
        { isVerified: true },
        { where: { id: emailCode.userId }, returning: true }
    );
    await emailCode.destroy();
    return res.json(user);
});

const login = catchError(async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    if (!user.isVerified) return res.status(401).json({ error: "Email not Valid" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "invalid credentials" });

    const token = jwt.sign(
        { user },
        process.env.TOKEN_SECRET,
        { expiresIn: '1d' }
    )

    return res.json({ user, token });
});

const getLoggerUser = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);
});

const resetPassword = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const result = await User.findOne({ where: { email } });
    
    const code = require('crypto').randomBytes(32).toString("hex");
    const link = `${frontBaseUrl}/auth/reset_password/${code}`
    await sendEmail({
        to: email,
        subject: 'Reset password',
        html: `
            <h1>Hello ${result.firstName} ${result.lastName}</h1>
            <br>
            <p>Verification link</p>
            <b>${link}</b>
        `
    });
    await EmailCode.create({
        code,
        userId: result.id
    })
    return res.status(401).json(result);
});

const newPassword = catchError(async(req, res) => {
    const { code } = req.params;
    const { password } = req.body;
    const emailCode = await EmailCode.findOne({ where: { code: code } });
    if (!emailCode) return res.status(401).json({ messaje: "error de código" })
    const encriptedPassword = await bcrypt.hash(password, 10);
    const {userId} = emailCode
    const result = await User.update(
        {password: encriptedPassword},
        { where: {id : userId}, returning: true}
        );
    return res.status(401).json(result);
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyCode,
    login,
    getLoggerUser,
    resetPassword,
    newPassword
}