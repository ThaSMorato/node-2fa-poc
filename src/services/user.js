const R = require("ramda");

const crypto = require("./crypto");
const { User } = require("../models");

const serializeUsers = (users) =>
  users.map((user) => user.get({ plain: true })).map(R.omit(["password"]));

const getUsers = () => User.findAll({}).then(serializeUsers);

const createUser = (user) =>
  crypto.hash(user.password).then((hash) =>
    User.create({
      ...user,
      password: hash,
    })
  );

const findByEmail = (email) => User.findOne({ where: { email } });

const findById = (id) => User.findOne({ where: { id } });

const addTwoFaSecret = (id, secret) =>
  User.update({ twoFaSecret: secret }, { where: { id } });

const activeTwoFactor = (id) =>
  User.update({ twoFaEneabled: true }, { where: { id } });

module.exports = {
  getUsers,
  createUser,
  findByEmail,
  findById,
  addTwoFaSecret,
  activeTwoFactor,
};
