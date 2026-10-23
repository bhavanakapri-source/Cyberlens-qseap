from datetime import datetime

from sqlalchemy.orm import Session

from .models import Conversation, Message, User


# ============================================================
# USER
# ============================================================

def get_user_by_email(
    db: Session,
    email: str,
):
    return (
        db.query(User)
        .filter(
            User.email == email
        )
        .first()
    )


def create_user(
    db: Session,
    name: str,
    email: str,
    password_hash: str,
):
    user = User(
        name=name,
        email=email,
        password_hash=password_hash,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def get_user(
    db: Session,
    user_id: int,
):
    return (
        db.query(User)
        .filter(
            User.id == user_id
        )
        .first()
    )


# ============================================================
# CONVERSATIONS
# ============================================================

def create_conversation(
    db: Session,
    user_id: int,
    title: str = "New Chat",
):
    conversation = Conversation(
        user_id=user_id,
        title=title,
    )

    db.add(conversation)
    db.commit()
    db.refresh(conversation)

    return conversation


def get_conversations(
    db: Session,
    user_id: int,
):

    return (
        db.query(Conversation)
        .filter(
            Conversation.user_id == user_id
        )
        .order_by(
            Conversation.updated_at.desc()
        )
        .all()
    )


def get_conversation(
    db: Session,
    conversation_id: int,
    user_id: int,
):

    return (
        db.query(Conversation)
        .filter(
            Conversation.id == conversation_id,
            Conversation.user_id == user_id,
        )
        .first()
    )


# ============================================================
# MESSAGES
# ============================================================

def add_message(
    db: Session,
    conversation_id: int,
    role: str,
    content: str,
):

    message = Message(
        conversation_id=conversation_id,
        role=role,
        content=content,
    )

    db.add(message)

    conversation = (
        db.query(Conversation)
        .filter(
            Conversation.id == conversation_id
        )
        .first()
    )

    if conversation:
        conversation.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(message)

    return message


def get_messages(
    db: Session,
    conversation_id: int,
):

    return (
        db.query(Message)
        .filter(
            Message.conversation_id
            == conversation_id
        )
        .order_by(
            Message.created_at
        )
        .all()
    )