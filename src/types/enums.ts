export enum UserRole {
    USER = 'USER',
    ADMIN = 'ADMIN',
    ORGANIZER = 'ORGANIZER'
}

export interface ITokenPayload {
    userId: string;
    role: UserRole;
    type: 'access' | 'refresh';
}


export enum EventCategory {
    CONFERENCE = 'CONFERENCE',
    WORKSHOP = 'WORKSHOP',
    SEMINAR = 'SEMINAR',
    NETWORKING = 'NETWORKING',
    SOCIAL = 'SOCIAL',
    OTHER = 'OTHER'
}

export enum EventStatus {
    DRAFT = 'DRAFT',
    PUBLISHED = 'PUBLISHED',
    CANCELLED = 'CANCELLED',
    COMPLETED = 'COMPLETED'
}

export enum ReservationStatus {
    PENDING = 'PENDING',
    CONFIRMED = 'CONFIRMED',
    CANCELLED = 'CANCELLED',
    COMPLETED = 'COMPLETED'
}