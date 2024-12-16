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
import { fileURLToPath } from 'url';
import multer from "multer";
import path from 'path';

dotenv.config()

const salt = 10

const app = express()

app.use(express.json())
app.use(cors())
app.use(cookieParser())

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
  const sql_check_if_exist = `select * from nguoidung where Email = ?`
  db.query(sql_check_if_exist, [req.body.email], (err, check_result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    if (check_result.length > 0) { // có người dùng với email này
      return res.json({ Status: 'Error', Error: 'Email này đã được đăng ký' })
    }
    else {
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
    }
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

  db.query(sql, (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    console.log(result);
    return res.json(result);
  })
})

app.get("/get-all-flight", (req, res) => {
  const sql = `
    SELECT *, DDXP.MaDiaDiem as maddxp, DDXP.TenDiaDiem as tenddxp, DDXP.TenSanBay as tensbxp,  DDD.MaDiaDiem as maddden, DDD.TenDiaDiem as tenddden, DDD.TenSanBay as tensbden
    FROM VE V JOIN CHUYENBAY CB ON V.MaChuyenBay = CB.MaChuyenBay 
    JOIN LOAIGHE LG on V.MaLoaiGhe = LG.MaLoaiGhe 
    JOIN HANG H ON CB.MaHang = H.MaHang
    JOIN DIADIEM DDXP ON CB.MaDiemXuatPhat = DDXP.MaDiaDiem
    JOIN DIADIEM DDD ON CB.MaDiemDen = DDD.MaDiaDiem
    JOIN MAYBAY MB ON CB.SoHieuMayBay = MB.SoHieuMayBay
    JOIN loaimaybay LMB ON MB.MaLoaiMayBay = LMB.MaLoaiMayBay
    GROUP BY CB.MaChuyenBay, LG.MaLoaiGhe
  `
  db.query(sql, (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    return res.json(result)
  })
})

app.get("/get-all-flight-with-condition", (req, res) => {
  const { mahang, madiemxp, madiemden } = req.query
  console.log('call me get-all-flight-with-condition: ', mahang, madiemxp, madiemden)
  const sql = `
    SELECT *, DDXP.MaDiaDiem as maddxp, DDXP.TenDiaDiem as tenddxp, DDXP.TenSanBay as tensbxp,  DDD.MaDiaDiem as maddden, DDD.TenDiaDiem as tenddden, DDD.TenSanBay as tensbden
    FROM VE V JOIN CHUYENBAY CB ON V.MaChuyenBay = CB.MaChuyenBay 
    JOIN LOAIGHE LG on V.MaLoaiGhe = LG.MaLoaiGhe 
    JOIN HANG H ON CB.MaHang = H.MaHang
    JOIN DIADIEM DDXP ON CB.MaDiemXuatPhat = DDXP.MaDiaDiem
    JOIN DIADIEM DDD ON CB.MaDiemDen = DDD.MaDiaDiem
    JOIN MAYBAY MB ON CB.SoHieuMayBay = MB.SoHieuMayBay
    JOIN loaimaybay LMB   ON MB.MaLoaiMayBay = LMB.MaLoaiMayBay
    WHERE H.MaHang = ? AND DDXP.MaDiaDiem = ? AND DDD.MaDiaDiem = ?
    GROUP BY CB.MaChuyenBay, LG.MaLoaiGhe
  `
  db.query(sql, [mahang, madiemxp, madiemden], (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    return res.json(result)
  })
})


//Lấy user với id
app.get('/get-user-by-id', (req, res) => {
  const { userid } = req.query;
  const sql = "SELECT * FROM nguoidung WHERE MaNguoiDung = ?";
  db.query(sql, [userid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting user by id' });
    else return res.json(result);
  })
})

//DÙNG MULTER CHO AVATAR USER
//Tạo nơi chứa ảnh (uploads)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueName = `${Date.now()}-${file.originalname}`; // Đặt tên tệp duy nhất
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage: storage
});


app.post('/upload-avatar', upload.single('avatar'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded!');
  }
  const fileUrl = `http://localhost:8800/uploads/${req.file.filename}`;
  res.status(200).json({ avatarUrl: fileUrl });
});


app.use('/uploads', express.static('uploads'));

//Cập nhật giá trị mới cho user
app.put('/update-user-info', (req, res) => {
  const {
    userid,
    userFullname,
    userPhone,
    userNation,
    userBirthday,
    userPassPort,
    useravatarurl
  } = req.body;
  const sql = `
    UPDATE nguoidung
    SET
      TenDayDu = ?,
      SDT = ?,
      QuocTich = ?,
      NgaySinh = ?,
      MaHoChieu = ?,
      Avatar = ?
    WHERE MaNguoiDung = ?
  `;
  db.query(sql, [userFullname, userPhone, userNation, userBirthday, userPassPort, useravatarurl, userid], (err, result) => {
    if (err) {
      console.error('Error updating user info:', err);
      return res.status(500).json({ error: 'Server error while updating user info' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ message: 'User updated successfully' });
  })
})

app.get("/get-all-tickets-by-MCB-and-MLG", (req, res) => {
  const { machuyenbay, maloaighe } = req.query
  const sql = `
    SELECT *
    FROM VE 
    WHERE MaChuyenBay = ? AND MaLoaiGhe =? AND DaBan = 0
  `
  db.query(sql, [machuyenbay, maloaighe], (err, result) => {
    if (err) return res.json({ Status: 'Error', Error: err })
    return res.json(result)
  })
})

app.post('/add-ctdv', (req, res) => {
  console.log('call me add-ctdv')
  const {
    MaNguoiDung,
    MaVe,
    TenDayDu,
    SDT,
    QuocTich,
    MaHoChieu,
    NgaySinh,
    NgayMua,
    TinhTrang } = req.body
  const values = [
    MaNguoiDung,
    MaVe,
    TenDayDu,
    SDT,
    QuocTich,
    MaHoChieu,
    NgaySinh,
    NgayMua,
    TinhTrang
  ]
  console.log('check req.body: ', values)
  const sql = `
    insert into chitietdatve(MaNguoiDung,MaVe,TenDayDu,SDT,QuocTich,MaHoChieu,NgaySinh,NgayMua,
    TinhTrang) value (?)
  `
  const sql_update_ticket = `
    update ve
    set DaBan = 1
    where MaVe = ?
  `
  db.query(sql, [values], (err, result) => {
    if (err) {
      console.log('Lỗi: ', err)
      return res.json({ Status: 'Error', Error: err })
    }
    db.query(sql_update_ticket, [MaVe], (update_err, update_result) => {
      if (update_err) {
        console.log('Lỗi: ', err)
        return res.json({ Status: 'Error', Error: update_err })
      }
      return res.json({ Status: 'Success' })
    })
  })
})

app.get('/get-chititetdatve-by-user-id', (req, res) => {
  const { userid } = req.query;
  const sql = `
  SELECT * , DDXP.MaDiaDiem AS MXP, DDXP.TenDiaDiem AS TXP, DDXP.TenSanBay AS SBXP, DDD.MaDiaDiem AS MD, DDD.TenDiaDiem AS TD, DDD.TenSanBay AS SBD
  FROM ChitietDatVe AS CTDV JOIN VE AS V 
  ON CTDV.Mave = V.MaVe JOIN ChuyenBay AS CB
  ON V.MaChuyenBay = CB.MaChuyenBay JOIN diadiem AS DDXP
  ON CB.MaDiemXuatPhat = DDXP.MaDiaDiem JOIN diadiem AS DDD 
  ON CB.MaDiemDen = DDD.MaDiaDiem JOIN LoaiGhe as LG ON LG.MALOAIGHE = V.MALOAIGHE
  Where CTDV.MaNguoiDung = ?`;
  db.query(sql, [userid], (err, result) => {
    if (err) return res.json({ Message: 'Error for getting chitietdatve by user id' });
    else return res.json(result);
  })
})

app.put('/update-chitietdatve-to-CXL', (req, res) => {
  const { ID_ChitietDatVe } = req.body;
  const sql = `UPDATE chitietdatve set TinhTrang = 'CXL' WHERE ID_ChitietDatVe = ?`;
  db.query(sql, [ID_ChitietDatVe], (err, result) => {
    if (err) {
      console.error('Error updating trang thai:', err);
      return res.status(500).json({ error: 'Server error while updating user info' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Chi tiet dat ve not found' });
    }

    return res.status(200).json({ message: 'Trang thai updated successfully' });
  })
})

app.listen(8800, () => {
  console.log("Connected to Backend. Keep moving forward http://localhost:8800");
})