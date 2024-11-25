import {ReservationStatus} from "@/types/enums";

export interface IReservation {
    id: string;
    eventId: string;
    userId: string;
    status: ReservationStatus;
    numberOfTickets: number;
    totalPrice: number;
    createdAt: Date;
    updatedAt: Date;
}

export interface IReservationCreate {
    eventId: string;
    numberOfTickets: number;
}
