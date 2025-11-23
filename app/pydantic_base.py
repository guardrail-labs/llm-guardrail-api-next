from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AppBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


__all__ = ["AppBaseModel"]
