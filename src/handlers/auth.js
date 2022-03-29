const auth = require("../services/auth");

const authenticate = async (ctx) => {
  const { email, password, twoFactorToken } = ctx.request.body;
  const {
    accessToken,
    refreshToken,
    refreshTokenExpiration,
    twoFactorEneabled,
  } = await auth.authenticate({ email, password, twoFactorToken });
  if (!accessToken && twoFactorEneabled) {
    ctx.body = { twoFactorEneabled };
  } else {
    ctx.cookies.set("refreshToken", refreshToken, {
      httpOnly: true,
      expires: refreshTokenExpiration,
    });
    ctx.body = {
      accessToken,
    };
  }
};

const refreshToken = async (ctx) => {
  const { accessToken, refreshToken, refreshTokenExpiration } =
    await auth.refreshToken({ token: ctx.cookies.get("refreshToken") });
  ctx.cookies.set("refreshToken", refreshToken, {
    httpOnly: true,
    expires: refreshTokenExpiration,
  });
  ctx.body = {
    accessToken,
  };
};

const logout = async (ctx) => {
  const { allDevices } = ctx.request.body;
  await auth.logout({ token: ctx.cookies.get("refreshToken"), allDevices });
  ctx.cookies.set("refreshToken", "");
  ctx.body = {};
};

const generateQrCode = async (ctx) => {
  const qrcode = await auth.generateQrCode(ctx.state.userId);

  ctx.body = `<img src=${qrcode}>`;
};

const activeTwoFactor = async (ctx) => {
  const { token } = ctx.request.body;

  await auth.activeTwoFactor(ctx.state.userId, token);

  ctx.body = { activated: true };
};

module.exports = {
  authenticate,
  refreshToken,
  logout,
  generateQrCode,
  activeTwoFactor,
};
