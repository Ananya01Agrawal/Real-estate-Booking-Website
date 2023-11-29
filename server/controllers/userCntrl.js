import {prisma} from '../config/prismaConfig.js';
import asynceHandler from 'express-async-handler'

const createUser = asynceHandler(async (req, res) => {
    console.log("Creating a user");

    let {email} = req.body;

    const userExists = await prisma.user.findUnique({
        where:{email:email}
    })

    if (!userExists) {
        const user = await prisma.user.create({
            data: req.body,
        });
        res.send({
            message: "User created successfully",
            user: user,
        });
    }
    else {
        res.status(201).send({
            message: "User already exists",
        });
    }
});

// bookvisit for residency

const bookVisit = asynceHandler(async (req, res) => {
    const {email,date} = req.body;
    const {id} = req.params;
    try {
        const alreadyBooked = await prisma.user.findUnique({
            where:{email},
            select:{bookedVisits :true}
        })
        if(alreadyBooked.bookedVisits.some((visit)=>visit.id===id)){
            res.status(400).json({message:"Already booked"})
        }
        else{
            await prisma.user.update({
                where:{email},
                data:{
                    bookedVisits:{ push:{ id, date}},
                },
            });
            res.status(200).send({message:"Booked successfully"})
        }
    } catch (error) {
        throw new Error(error.message)
    }
});

const getAllBookings = asynceHandler(async (req, res) => {   
    const {email} = req.body;
    try {
        const bookings = await prisma.user.findUnique({
            where:{email},
            select:{bookedVisits :true}
        })
        res.status(200).send(bookings)
    } catch (error) {
        throw new Error(error.message)
    }
});

const cancelBooking = asynceHandler(async (req, res) => {
    const {email} = req.body;
    const {id} = req.params;
    try {
        const user = await prisma.user.findUnique({
            where:{email},
            select:{bookedVisits :true}
        })
        
        const index = user.bookedVisits.findIndex((visit)=>visit.id===id)

        if(index === -1){
            res.status(400).json({message:"Not booked"})
        }
        else{
            user.bookedVisits.splice(index,1)
            await prisma.user.update({
                where:{email},
                data:{
                    bookedVisits:user.bookedVisits
                }
            })
            res.status(200).send({message:"Cancelled successfully"})
        }
    } catch (error) {
        throw new Error(error.message)
        
    }
});

const toFav = asynceHandler(async (req, res) => {
    const {email}=req.body;
    const {rid} = req.params;
    
    try {
        const user = await prisma.user.findUnique({
            where:{email}
        })
        if(user.favResidenciesID.includes(rid)){
            const updateUser = await prisma.user.update({
                where:{email},
                data:{
                    favResidenciesID:{
                        set:user.favResidenciesID.filter((id)=>id!==rid)
                    },
                },
            });
            res.status(200).send({message:"Removed from fav",user:updateUser})
        }
        else{
            const updateUser = await prisma.user.update({
                where:{email},
                data:{
                    favResidenciesID:{
                        push:rid
                    },
                },
            });
            res.status(200).send({message:"Added to fav",user:updateUser});
        }
    } catch (error) {
        throw new Error(error.message)
    }
});

const getAllFav = asynceHandler(async (req, res) => {
    const {email} = req.body;
    try {
        const user = await prisma.user.findUnique({
            where:{email},
            select:{favResidenciesID:true}
        })
        res.status(200).send(user)
    } catch (error) {
        throw new Error(error.message)
    }
});

export {createUser,bookVisit,getAllBookings ,cancelBooking ,toFav , getAllFav};