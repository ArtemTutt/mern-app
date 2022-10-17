import jwt from "jsonwebtoken";


export default (req, res, next) => {

    // получение токена
    const token = (req.headers.authorization || '').replace(/Bearer\s?/, "");


    // Получаем токен, если он есть, то расшифровываем его
    if(token) {
        try {
            const  decode = jwt.verify(token, 'secret123');

            req.userID = decode._id;
            next();
        } catch (err) {
            return res.status(403).json({
                message: err
            })
        }
    } else {
        return  res.status(403).json({
            message: 'Нет доступа'
        })
    }

    // res.send(token)
}