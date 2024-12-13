import express from "express";
import mysql from "mysql";
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import dotenv from 'dotenv'
import axios from 'axios'
import CryptoJS from 'crypto-js'
import nodemailer from 'nodemailer'
import cookieParser from 'cookie-parser'

dotenv.config()

const salt = 10

const app = express()

app.use(express.json())
app.use(cors())
app.use(cookieParser())

//Kết nối tới database crud trên MySQL mở bằng Xampp
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'tour_king'
})

function authenToken(req, res, next) {
  const authorizationHeader = req.headers['authorization'] // <string>: `Bearer {token}`
  if (!authorizationHeader) return res.status(401).json({ error: 'Authorization header is missing' });
  const token = authorizationHeader.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Token is missing' }); // Unauthorized error
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, data) => {
    console.log(err, data)
    if (err) return res.sendStatus(403) // Forbidden error
    console.log('authorization successfully !')
    next() // complete verify token 
  })
}

app.get("/", (req, res) => {
  return res.json("Hello backend")
})

app.post('/register', (req, res) => {
  console.log('call me register')
  const sql = 'insert into nguoidung(Email, Matkhau) values (?)'
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Error: 'error for hashing password' })
    const values = [
      req.body.email,
      hash,
    ]
    db.query(sql, [values], (err, result) => {
      if (err) return res.json({ Status: 'Error', Error: err })
      return res.json({ Status: 'Success' })
    })
  })
})

app.post('/login', (req, res) => {
  const sql = 'select * from nguoidung where Email = ?'
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Status: 'Error', Error: 'Login error in server' })
    if (data.length > 0) { // có người dùng với email này
      bcrypt.compare(req.body.password.toString(), data[0].MatKhau, (err, response) => {
        if (err) return res.json({ Status: 'Error', Error: 'Password compare error' })
        if (response) {
          const userid = data[0].MaNguoiDung
          const name = data[0].TenDayDu // có nguy cơ lỗi
          const isadmin = data[0].Admin
          const useravatarurl = data[0].Avatar
          const accessToken = jwt.sign({ userid, name, isadmin, useravatarurl }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60m' })
          const refreshToken = jwt.sign({ userid, name, isadmin, useravatarurl }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' })
          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: false, // set to true when deploy to production
            path: '/',
            sameSite: 'strict'
          })
          // // Lưu refresh token vào database
          // const updateTokenSql = 'UPDATE user SET refreshtoken = ? WHERE useremail = ?';
          // db.query(updateTokenSql, [refreshToken, req.body.email], (err) => {
          //   if (err) return res.json({ Error: 'Error updating refresh token' });
          //   return res.json({ Status: 'Success', accessToken, refreshToken });
          // });
          return res.json({ Status: 'Success', accessToken, refreshToken })
        }
        else {
          return res.json({ Status: 'Error', Error: 'Mật khẩu không đúng' })
        }
      })
    } else {
      return res.json({ Status: 'Error', Error: 'Không tồn tại người dùng với email này !' })
    }
  })
})
//Lấy user theo email
app.get('/get-user-by-email', (req, res) => {
  console.log('call me get-user-by-email')
  const { email } = req.query
  const sql = "SELECT * FROM nguoidung where Email = ?";
  db.query(sql, [email], (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err });
    else return res.json(result);
  })
})
app.post('/send-recovery-email', async (req, res) => {
  console.log('call me send-recovery-email')
  const { OTP, recipient_email } = req.body
  console.log('check opt and recipient-email: ', OTP, recipient_email)
  if (!recipient_email) {
    return res.status(400).json({ message: 'Email address is required!' });
  }
  //Cấu hình transporter (sử dụng gmail)
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false, // true for port 465, false for other ports
    auth: {
      user: process.env.MAIL_USERNAME,
      pass: process.env.MAIL_PASSWORD,
    },
  });
  try {
    const info = await transporter.sendMail({
      from: '"Maddison Foo Koch 👻" <huynhanh.170504@gmail.com>', // sender address
      to: recipient_email, // list of receivers
      subject: "Hello ✔", // Subject line
      text: "YOUR OTP CODE: " + OTP, // plain text body
      html: "<b>YOUR OTP CODE: " + OTP + "</b>", // html body
    });
    console.log('Email sent: ' + info);
  }
  catch (err) {
    return res.json({ Status: 'Error', Error: err })
  }
  return res.json({ Status: 'Success' })
})
app.post('/update-password-by-email', (req, res) => {
  console.log('call me update password-by-email')
  const { resetEmail, password } = req.body
  console.log('check resetEmail and password: ', resetEmail, password) //check resetEmail and password:  huynhanh.170504@gmail.com 321
  const sql = `
    update nguoidung
    set matkhau = ?
    where email = ?
  `
  bcrypt.hash(password.toString(), salt, (err, hash) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    db.query(sql, [hash, resetEmail], (err, result) => {
      if (err) return res.json({ Status: 'Error', Error: err })
      return res.json({ Status: 'Success' })
    })
  })
})
app.get("/get-flight-by-airline", (req, res) => {
  console.log('call me get-flight-by-airline')
  const { destination, airline } = req.query
  const sql = `
    SELECT * 
    FROM CHUYENBAY CB 
    JOIN DIADIEM DD ON CB.MADIEMDEN = DD.MADIADIEM
    JOIN HANG ON CB.MAHANG = HANG.MAHANG
    WHERE TENDIADIEM = ? AND TENHANG = ?
  `
  // const sql = 'select * from nguoidung'
  db.query(sql, [destination, airline], (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    console.log(result)
    return res.json(result)
  })
})

//Lấy hết data vé máy bay
app.get("/get-all-ticket-info", (req, res) => {
  console.log('Ready to get all ticket info!!!');
  const sql = `
  SELECT *, DDXP.MaDiaDiem as maddxp, DDXP.TenDiaDiem as tenddxp, DDXP.TenSanBay as tensbxp,  DDD.MaDiaDiem as maddden, DDD.TenDiaDiem as tenddden, DDD.TenSanBay as tensbden
  FROM VE V JOIN CHUYENBAY CB ON V.MaChuyenBay = CB.MaChuyenBay 
  JOIN LOAIGHE LG on V.MaLoaiGhe = LG.MaLoaiGhe 
  JOIN HANG H ON CB.MaHang = H.MaHang
  JOIN DIADIEM DDXP ON CB.MaDiemXuatPhat = DDXP.MaDiaDiem
  JOIN DIADIEM DDD ON CB.MaDiemDen = DDD.MaDiaDiem
  JOIN MAYBAY MB ON CB.SoHieuMayBay = MB.SoHieuMayBay
  JOIN loaimaybay LMB ON MB.MaLoaiMayBay = LMB.MaLoaiMayBay
  `

  db.query(sql, (err,result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    console.log(result);
    return res.json(result);
  })
})

app.listen(8800, () => {
  console.log("Connected to Backend. Keep moving forward http://localhost:8800");
})