
export default function (req, res, next) {

    if (!req.headers.authorization) {
        return res.status(401).json({message: "Du har ikke adgang til denne funktionalitet!"})
    }
// afkode jwt
// tjek jwt
    if(req.headers.authorization != "Bearer 12345678") {
        return res.status(403).json({mesage: "Ugyldig nøgle"})
    }

    next()
}


// JSON Web Tokens (JWT) 
// 