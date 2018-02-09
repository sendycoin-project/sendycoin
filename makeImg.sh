#!/bin/sh

function createDmg {
  NAME=$1
  
  sudo ../contrib/macdeploy/macdeployqtplus ${NAME}.app
  sudo chown -R Christophe ${NAME}.app/Contents/Frameworks/*
  mkdir -p ${NAME}
  [ -d ${NAME}/${NAME}.app ] &&  rm -rf ${NAME}/${NAME}.app
  cp -r ${NAME}.app ${NAME}/
  rm tmp_${NAME}.dmg
  hdiutil create tmp_${NAME}.dmg -srcfolder ${NAME}/
  mkdir -p output
  rm -rf output/*
  hdiutil convert -format UDZO -o output/${NAME}.dmg tmp_${NAME}.dmg
}

createDmg $1