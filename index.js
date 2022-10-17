import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import mongoose from "mongoose";
import {registerValidation} from "./validations/auth.js";
import { validationResult } from "express-validator";
import UserSchema from "./models/User.js";
import checkAuth from "./middleware/checkAuth.js";



mongoose.connect(
    'mongodb+srv://admin:admin@cluster0.bbqrakp.mongodb.net/MERN?retryWrites=true&w=majority'
).then(() => {
    console.log('DB ok')
}).catch((err) => {
    console.warn(err)
})

const app = express();
app.use(express.json());


// Авторизация
app.post('/auth/login', async (req, res) => {
    try {
        const user = await UserSchema.findOne({ email: req.body.email });

        if(!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            })
        }

        // Проверка на совпадение пароля
        const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash);
        if(!isValidPass) {
            return res.status(400).json({
                message: 'Неверный логин или пароль('
            })
        }

        const token = jwt.sign({
                _id: user._id
            },
            'secret123',
            {
                expiresIn: '30d'
            });

        const {passwordHash, ...userData} = user._doc;

        // Наш ответ с бэка на сторону клиента
        res.json({
            ...userData,
            token
        })
    } catch (err) {
        console.warn(err)
    }
})


// Регистрация
app.post('/auth/register', registerValidation, async (req, res) => {
    try {
        const error = validationResult(req); // проверка на корректность через валидатор
        if(!error.isEmpty()) {
            return res.status(400).json(error.array())
        }


        // Процесс шифровки пароля через bcrypt
        const password = req.body.password
        const  salt = await bcrypt.genSalt(10)
        const hash = await bcrypt.hash(password, salt);

        // Создание пользователя
        const doc = new UserSchema({
            email: req.body.email,
            fullName: req.body.fullName,
            avatarUrl: req.body.avatarUrl,
            passwordHash: hash
        });

        // Создание пользователя в MongoDB
        const user = await doc.save();

        // Создание токена по шифровки id
        const token = jwt.sign({
            _id: user._id
        },
            'secret',
            {
                expiresIn: '30d'
            });


        // Вытаскиваем passwordHash и возвращаем все остальное, а именно userData
        const {passwordHash, ...userData} = user._doc;

        // Наш ответ с бэка на сторону клиента
        res.json({
            ...userData,
            token
        })
    }
    catch (err) {
        console.log(err)
        res.status(500).json({
            mes: "Не удалось произвести регистрацию"
        })
    }
});

// Провера авторизован пользователь или нет
app.get('/auth/me', checkAuth, async (req, res) => {
    try {
        const user = await UserSchema.findById(req.userID);

        if(!user) {
            return res.status(404).json({
                message: 'Пользователь не найден'
            })
        }
        const {passwordHash, ...userData} = user._doc;

        // Наш ответ с бэка на сторону клиента
        res.json(userData)
    } catch (err) {

    }
})


// Настройка сервера
app.listen(3000, (err) => {
    if (err) {
        return console.warn(err)
    }
    console.log('Сервер работает...')
})