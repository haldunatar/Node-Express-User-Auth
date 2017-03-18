module.exports = {
  sendgrid: {
    user: process.env.SENDGRID_USER || 'yourUserName',
    password: process.env.SENDGRID_PASSWORD || 'yourPass'
  }
};
