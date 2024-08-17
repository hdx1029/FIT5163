# Created by Pasindu Epa <pasindu.epa@monash.edu> on 03/07/2024
#!/bin/bash
PROJECT_NAME="Monash"
PROJECT_SAVE_AS=${PROJECT_NAME}
DOWNLOAD_AS="/home/$SUDO_USER/GNS3/projects/${PROJECT_NAME}.tar.xz"
PROJECTS_DIR="/home/$SUDO_USER/GNS3/projects"
CURRENT_PID="9165f56e13ae"

read -p "Running this script will overwrite any existing Monash projects which you have already installed on this machine. Do you want to continue (y/n)?" choice
case "$choice" in 
  y|Y ) 

	rm -R "${PROJECTS_DIR}/${PROJECT_SAVE_AS}"

## Code begins
cp "./${PROJECT_NAME}.tar.xz" ${DOWNLOAD_AS}

#Extracting project
echo "Extracting project:"
mkdir "${PROJECTS_DIR}/${PROJECT_SAVE_AS}"
tar -xf ${DOWNLOAD_AS} -C "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/" --checkpoint=.1000

#Move Files
mv "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_NAME}"/* "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/"
rmdir "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_NAME}/" 
mv "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_NAME}.gns3" "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_SAVE_AS}.gns3"
rm ${DOWNLOAD_AS}
#Change project permissions and ownership
chmod 775 -R "${PROJECTS_DIR}/${PROJECT_SAVE_AS}"
chown -R $SUDO_USER:$SUDO_USER "${PROJECTS_DIR}/${PROJECT_SAVE_AS}"

#Update Project ID
NEW_PID=$(xxd -u -l 6 -p /dev/urandom)
sed -i "s/${CURRENT_PID}/${NEW_PID}/" "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_SAVE_AS}.gns3"
sed -i "s/${PROJECT_NAME}/${PROJECT_SAVE_AS}/" "${PROJECTS_DIR}/${PROJECT_SAVE_AS}/${PROJECT_SAVE_AS}.gns3"
printf '%s\n'
echo "${PROJECT_NAME} project was successfully installed as ${PROJECT_SAVE_AS}."
printf '%s\n'
## Code ends

;;
  n|N ) echo "";;
esac



