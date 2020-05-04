const nodemailer = require('nodemailer');
const config = require('config.json');

module.exports = sendEmail;

function sendEmail({ to, subject, html, from = config.emailFrom }) {
    const transporter = nodemailer.createTransport(config.smtpOptions);
    transporter.sendMail({ from, to, subject, html });
}