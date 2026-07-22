from pydantic import BaseModel


class MayaQuestion(BaseModel):

    question: str
