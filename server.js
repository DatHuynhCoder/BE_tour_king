import express from "express";
import mysql from "mysql";

const app = express()

//Kết nối tới database crud trên MySQL mở bằng Xampp
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'tour_king'
})

app.get("/", (req,res) => {
  res.json("Hello backend")
})

app.listen(8800, () => {
  console.log("Connected to Backend. Keep moving forward");
})