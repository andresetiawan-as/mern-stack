const express = require('express')
const router = express.Router()
const gravatar = require('gravatar')
const bycrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const{ check, validationResult } = require('express-validator')

// Model Schema
const User = require('../../models/User')

// @route   POST api/users
// @desc    Register User
// @access  Public
router.post('/', [
    check('name', 'Name is required')
        .not()
        .isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({min: 6})
], 
async (req, res) => {
    // Checking error from body req
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }
    const { name, email, password } = req.body

    try {
        // See if user exists
        let user = await User.findOne({email});
        if(user){
            return res.status(400).json({errors: [{msg: 'User already exists'}] });
        }

        // Get users gravatar
        const avatar = gravatar.url(email,{
            size: '200',
            reading: 'pg',
            default: 'mm'
        })
        user = new User({
            name,
            email,
            avatar,
            password
        });

        // Excript password bycrypt
        const salt = await bycrypt.genSalt(10);
        user.password = await bycrypt.hash(password, salt);
        await user.save();

        // Return jsonwebtoken
        const payload = {
            user: {
                id: user.id
            }
        }
        jwt.sign(
            payload,
            config.get('jwtSecret'),
            {expiresIn: 36000},
            (err, token) => {
                if(err) throw err;
                res.json({ token });
            }
        )

        // res.send('User registered')
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Server error');
    }
})

module.exports = router