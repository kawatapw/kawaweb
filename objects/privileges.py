# -*- coding: utf-8 -*-

from enum import IntFlag
from enum import unique
from typing import Union, List

__all__ = ("Privileges",)


@unique
class Privileges(IntFlag):
    """Server side user privileges."""

    Banned = 0  # 0 Perms, Banned or Restricted, whatever you want to call it.
    Normal = 1  # user is not restricted.
    Verified = 2 << 0  # has logged in to the server in-game.
    Supporter = 2 << 1  # user is a supporter.
    AccessPanel = 2 << 2  # probably wont be used much.
    ManageUsers = (
        2 << 3
    )  # can manage users? probably going to be used for changing passwords/email/etc
    RestrictUsers = 2 << 4  # can ban users
    SilenceUsers = 2 << 5  # can silence users
    WipeUsers = 2 << 6  # can wipe users
    ManageBeatmaps = 2 << 7  # able to manage maps ranked status.
    ManageBadges = 2 << 13  # can manage badges
    ViewPanelLog = 2 << 14  # can view the panel log
    ManagePrivs = 2 << 15  # can manage privs of users
    SendAlerts = 2 << 16  # can send in-game alerts? probably not going to be used much
    ChatMod = 2 << 17  # chat mod, no way
    KickUsers = 2 << 18  # can kick users
    Tournament = 2 << 20  # able to manage match state without host.
    ManageClans = 2 << 27  # can manage clans.
    ViewSensitiveInfo = (
        2 << 28
    )  # can view ips, hwids, disk ids of users. super awesome with the new system.
    IsBot = 2 << 30  # BOT_USER
    Whitelisted = 2 << 31  # has bypass to low-ceiling anticheat measures (trusted).
    Premium = 2 << 32  # 'premium' donor
    Alumni = 2 << 33  # notable users, receives some extra benefits.
    Dangerous = 2 << 34  # able to manage full server app.state.

    # groups inherently say they "are part of" the things they contain.
    # e.g. if you have the AccessPanel privilege, you are also a Moderator, Admin, and Nominator..
    # like... it thinks you are all of those things. a pain in my ass.
    # so, when operating with privileges. please use the following syntax, or just use GetPriv, since its already coded.
    # Format:
    # if user_priv & Privileges.Mod == Privileges.Mod
    # this is to check if a user has ALL privileges in a group; like mod.
    # to check if a privilege is IN a group, like donator, or staff,  you do
    # if user_priv & Privileges.Donator. thats it.

    Nominator = ManageBeatmaps | AccessPanel
    SUPPORT = (
        RestrictUsers
        | SilenceUsers
        | WipeUsers
        | KickUsers
        | ChatMod
        | ViewPanelLog
        | SendAlerts
        | ManageClans
        | AccessPanel
    )
    Mod = (
        SUPPORT | ManageUsers | ManageBadges | ViewSensitiveInfo
    )  # define this as a moderator
    Admin = Mod | ManagePrivs  # has moderator privileges, can view sensitive info

    Donator = Supporter | Premium
    Staff = Mod | Admin | Dangerous


def GetPriv(priv: Union[int, List[Privileges]]) -> Union[int, List[Privileges]]:
    """
    Get the privileges based on the given input.

    Args:
        priv (Union[int, List[Privileges]]): The input representing the privileges. It can be either an integer or a list of Privileges instances.

    Returns:
        Union[int, List[Privileges]]: The privileges based on the input.
        If the input is an integer, it returns a list of Privileges instances that match the input.
        If the input is a list of Privileges instances, it returns an integer representing the combined privileges.

    Raises:
        TypeError: If the input is not an integer or a list of Privileges instances.
        ValueError: If no privileges are found.
    """
    if isinstance(priv, int):
        privs = [p for p in Privileges if p.value != 0 and priv & p.value == p.value]

    elif isinstance(priv, list) and all(isinstance(p, Privileges) for p in priv):
        privs = 0
        for p in priv:
            privs |= p.value
    else:
        raise TypeError("Privilege must be an int or a list of instances of Privileges")

    if not privs:
        raise ValueError("No Privileges")

    return privs


def ComparePrivs(
    l1: Union[int, List[Privileges]], l2: Union[int, List[Privileges]]
) -> bool:
    if isinstance(l1, int):
        l1 = GetPriv(l1)
    if isinstance(l2, int):
        l2 = GetPriv(l2)

    s1 = set(l1)
    s2 = set(l2)

    # remove privs that dont matter
    s1.discard(Privileges.Supporter)
    s1.discard(Privileges.Premium)
    s1.discard(Privileges.Alumni)
    s2.discard(Privileges.Supporter)
    s2.discard(Privileges.Premium)
    s2.discard(Privileges.Alumni)

    return s2.issubset(s1)
