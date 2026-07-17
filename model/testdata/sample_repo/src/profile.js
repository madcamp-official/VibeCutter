const express = require("express");
const router = express.Router();

function renderProfile(req, res) {
  // 취약: 사용자 입력을 이스케이프 없이 응답에 반영 (reflected XSS)
  res.send("<h1>Hello " + req.query.name + "</h1>");
}

const listOrders = async (req, res) => {
  const orders = await db.orders.find({ userId: req.params.userId });
  res.json(orders);
};

module.exports = { renderProfile, listOrders };
