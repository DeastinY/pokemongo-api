# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: LocalPlayer.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()

from Player import AvatarDetails_pb2 as Player_dot_AvatarDetails__pb2
from Player import DailyBonus_pb2 as Player_dot_DailyBonus__pb2
from Player import EquippedBadge_pb2 as Player_dot_EquippedBadge__pb2
Enums_dot_BadgeType__pb2 = Player_dot_EquippedBadge__pb2.Enums_dot_BadgeType__pb2
from Player import ContactSettings_pb2 as Player_dot_ContactSettings__pb2
from Player import Currency_pb2 as Player_dot_Currency__pb2

from Player.AvatarDetails_pb2 import *
from Player.DailyBonus_pb2 import *
from Player.EquippedBadge_pb2 import *
from Player.ContactSettings_pb2 import *
from Player.Currency_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='LocalPlayer.proto',
  package='POGOProtos',
  syntax='proto3',
  serialized_pb=_b('\n\x11LocalPlayer.proto\x12\nPOGOProtos\x1a\x1aPlayer/AvatarDetails.proto\x1a\x17Player/DailyBonus.proto\x1a\x1aPlayer/EquippedBadge.proto\x1a\x1cPlayer/ContactSettings.proto\x1a\x15Player/Currency.proto\"\xb5\x03\n\x0bLocalPlayer\x12\x1d\n\x15\x63reation_timestamp_ms\x18\x01 \x01(\x03\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x0c\n\x04team\x18\x05 \x01(\x05\x12\x19\n\x11tutorial_complete\x18\x07 \x01(\x0c\x12\x38\n\x0e\x61vatar_details\x18\x08 \x01(\x0b\x32 .POGOProtos.Player.AvatarDetails\x12\x1b\n\x13max_pokemon_storage\x18\t \x01(\x05\x12\x18\n\x10max_item_storage\x18\n \x01(\x05\x12\x32\n\x0b\x64\x61ily_bonus\x18\x0b \x01(\x0b\x32\x1d.POGOProtos.Player.DailyBonus\x12\x38\n\x0e\x65quipped_badge\x18\x0c \x01(\x0b\x32 .POGOProtos.Player.EquippedBadge\x12<\n\x10\x63ontact_settings\x18\r \x01(\x0b\x32\".POGOProtos.Player.ContactSettings\x12/\n\ncurrencies\x18\x0e \x03(\x0b\x32\x1b.POGOProtos.Player.CurrencyP\x00P\x01P\x02P\x03P\x04\x62\x06proto3')
  ,
  dependencies=[Player_dot_AvatarDetails__pb2.DESCRIPTOR,Player_dot_DailyBonus__pb2.DESCRIPTOR,Player_dot_EquippedBadge__pb2.DESCRIPTOR,Player_dot_ContactSettings__pb2.DESCRIPTOR,Player_dot_Currency__pb2.DESCRIPTOR,])
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_LOCALPLAYER = _descriptor.Descriptor(
  name='LocalPlayer',
  full_name='POGOProtos.LocalPlayer',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='creation_timestamp_ms', full_name='POGOProtos.LocalPlayer.creation_timestamp_ms', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='username', full_name='POGOProtos.LocalPlayer.username', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='team', full_name='POGOProtos.LocalPlayer.team', index=2,
      number=5, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='tutorial_complete', full_name='POGOProtos.LocalPlayer.tutorial_complete', index=3,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='avatar_details', full_name='POGOProtos.LocalPlayer.avatar_details', index=4,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='max_pokemon_storage', full_name='POGOProtos.LocalPlayer.max_pokemon_storage', index=5,
      number=9, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='max_item_storage', full_name='POGOProtos.LocalPlayer.max_item_storage', index=6,
      number=10, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='daily_bonus', full_name='POGOProtos.LocalPlayer.daily_bonus', index=7,
      number=11, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='equipped_badge', full_name='POGOProtos.LocalPlayer.equipped_badge', index=8,
      number=12, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='contact_settings', full_name='POGOProtos.LocalPlayer.contact_settings', index=9,
      number=13, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='currencies', full_name='POGOProtos.LocalPlayer.currencies', index=10,
      number=14, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=168,
  serialized_end=605,
)

_LOCALPLAYER.fields_by_name['avatar_details'].message_type = Player_dot_AvatarDetails__pb2._AVATARDETAILS
_LOCALPLAYER.fields_by_name['daily_bonus'].message_type = Player_dot_DailyBonus__pb2._DAILYBONUS
_LOCALPLAYER.fields_by_name['equipped_badge'].message_type = Player_dot_EquippedBadge__pb2._EQUIPPEDBADGE
_LOCALPLAYER.fields_by_name['contact_settings'].message_type = Player_dot_ContactSettings__pb2._CONTACTSETTINGS
_LOCALPLAYER.fields_by_name['currencies'].message_type = Player_dot_Currency__pb2._CURRENCY
DESCRIPTOR.message_types_by_name['LocalPlayer'] = _LOCALPLAYER

LocalPlayer = _reflection.GeneratedProtocolMessageType('LocalPlayer', (_message.Message,), dict(
  DESCRIPTOR = _LOCALPLAYER,
  __module__ = 'LocalPlayer_pb2'
  # @@protoc_insertion_point(class_scope:POGOProtos.LocalPlayer)
  ))
_sym_db.RegisterMessage(LocalPlayer)


# @@protoc_insertion_point(module_scope)