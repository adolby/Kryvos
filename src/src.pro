TEMPLATE = subdirs
SUBDIRS += core plugins tests quick widgets
CONFIG += ordered

android|ios {
  SUBDIRS -= widgets
}
