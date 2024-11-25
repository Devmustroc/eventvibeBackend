import {EventCategory, EventStatus} from "@/types/enums";

export interface IEvent {
    id: string;
    title: string;
    description: string;
    location: string;
    city: string;
    zipCode: string;
    country: string;
    startDate: Date;
    endDate: Date;
    price: number;
    capacity: number;
    remainingSpots: number;
    category: EventCategory;
    status: EventStatus;
    images: string[];
    organizerId: string;
    createdAt: Date;
    updatedAt: Date;
}

export interface IEventCreate extends Omit<IEvent, 'id' | 'createdAt' | 'updatedAt' | 'organizerId' | 'remainingSpots'> {
    organizerId?: string;
}