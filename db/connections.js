const mysql = require('mysql2');
const dotenv = require('dotenv');

dotenv.config();

const database = {
    DB_HOST: "localhost",
    DB_USER:"root",
    DB_PASSWORD:"utesa",
    DB_NAME:"projects",
    DB_PORT:3306,
    PORT:3000
}

const pool = mysql.createPool({
  host: database.DB_HOST,
  user: database.DB_USER,
  password: database.DB_PASSWORD,
  database: database.DB_NAME,
  port: database.DB_PORT,
});

module.exports = pool.promise();