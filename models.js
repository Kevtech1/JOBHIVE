const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema (for job seekers)
const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'First name is required'],
        trim: true,
        minlength: [2, 'First name must be at least 2 characters long'],
        maxlength: [30, 'First name cannot exceed 30 characters'],
        match: [/^[A-Za-z\s]+$/, 'First name can only contain letters and spaces']
    },
    lastName: {
        type: String,
        required: [true, 'Last name is required'],
        trim: true,
        minlength: [2, 'Last name must be at least 2 characters long'],
        maxlength: [30, 'Last name cannot exceed 30 characters'],
        match: [/^[A-Za-z\s]+$/, 'Last name can only contain letters and spaces']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        trim: true,
        match: [/^[0-9+\s-]{10,15}$/, 'Please enter a valid phone number']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters long'],
        match: [
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/,
            'Password must contain at least one uppercase letter, one lowercase letter, and one number'
        ]
    },
    userType: {
        type: String,
        enum: ['jobseeker', 'employer'],
        default: 'jobseeker'
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

// Employer Schema
const employerSchema = new mongoose.Schema({
    companyName: {
        type: String,
        required: [true, 'Company name is required'],
        trim: true,
        minlength: [2, 'Company name must be at least 2 characters long'],
        maxlength: [50, 'Company name cannot exceed 50 characters'],
        match: [/^[A-Za-z0-9\s]+$/, 'Company name can only contain letters, numbers, and spaces']
    },
    companyRegNumber: {
        type: String,
        required: [true, 'Company registration number is required'],
        unique: true,
        trim: true,
        match: [/^[A-Z0-9]{5,20}$/, 'Please enter a valid registration number']
    },
    companyEmail: {
        type: String,
        required: [true, 'Company email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
    },
    companyPhone: {
        type: String,
        required: [true, 'Company phone is required'],
        trim: true,
        match: [/^[0-9+\s-]{10,15}$/, 'Please enter a valid phone number']
    },
    companyWebsite: {
        type: String,
        trim: true,
        match: [/^https?:\/\/.+$/, 'Please enter a valid website URL']
    },
    companyAddress: {
        type: String,
        required: [true, 'Company address is required'],
        trim: true,
        minlength: [10, 'Company address must be at least 10 characters long'],
        maxlength: [200, 'Company address cannot exceed 200 characters']
    },
    contactPersonName: {
        type: String,
        required: [true, 'Contact person name is required'],
        trim: true,
        minlength: [2, 'Contact person name must be at least 2 characters long'],
        maxlength: [50, 'Contact person name cannot exceed 50 characters'],
        match: [/^[A-Za-z\s]+$/, 'Contact person name can only contain letters and spaces']
    },
    contactPersonPosition: {
        type: String,
        required: [true, 'Contact person position is required'],
        trim: true,
        minlength: [2, 'Contact person position must be at least 2 characters long'],
        maxlength: [50, 'Contact person position cannot exceed 50 characters'],
        match: [/^[A-Za-z\s]+$/, 'Contact person position can only contain letters and spaces']
    },
    contactPersonEmail: {
        type: String,
        required: [true, 'Contact person email is required'],
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
    },
    contactPersonPhone: {
        type: String,
        required: [true, 'Contact person phone is required'],
        trim: true,
        match: [/^[0-9+\s-]{10,15}$/, 'Please enter a valid phone number']
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationStatus: {
        type: String,
        enum: ['pending', 'verified', 'rejected'],
        default: 'pending'
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

// Create indexes for better query performance
userSchema.index({ email: 1 });
employerSchema.index({ companyEmail: 1 });
employerSchema.index({ companyRegNumber: 1 });

// Create models
const User = mongoose.model('User', userSchema);
const Employer = mongoose.model('Employer', employerSchema);

module.exports = {
    User,
    Employer
}; 