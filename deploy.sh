#!/bin/bash

### TODO: nodeEnv is missing when installing ZSH for first user

shell=bash

if [ $shell = 'bash' ]; then
  esc='\E'
  echo='echo -ne'
else
  esc='\033'
  echo='echo'
fi

## foreground colors ##
GREEN="$esc[32;1m"
RED="$esc[31;1m"
BLUE="$esc[34;1m"
YELLOW="$esc[33;1m"
BLACK="$esc[30;1m"
MAGENTA="$esc[35;1m"
CYAN="$esc[36;1m"
WHITE="$esc[37;1m"

## combo colors - FG_BG ##
WHITEBLUE="$esc[37;44;1m"
WHITEMAGENTA="$esc[37;45;1m"

## reset terminal to default ##
REVERT="$esc[0m"

## Only run this script as root ##
if [ ! `whoami` = root ]; then
  $echo "\n${RED}This script must be run from the root user.${REVERT}\n"
  exit
fi

no="[y/${CYAN}N${GREEN}]"
yes="[${GREEN}Y${CYAN}/n]"


##     ##    ###    ########   ######
##     ##   ## ##   ##     ## ##    ##
##     ##  ##   ##  ##     ## ##
##     ## ##     ## ########   ######
 ##   ##  ######### ##   ##         ##
  ## ##   ##     ## ##    ##  ##    ##
   ###    ##     ## ##     ##  ######




 #######  ########  ########  ######
##     ## ##     ##    ##    ##    ##
##     ## ##     ##    ##    ##
##     ## ########     ##     ######
##     ## ##           ##          ##
##     ## ##           ##    ##    ##
 #######  ##           ##     ######
 # Collect options #

function collectAdminUserInfo(){
  while true; do
    $echo "\t${YELLOW}➜ Enter username you want to use on this system:${REVERT} "
    read username

    if [ ! "${username}" ]; then
      $echo "\t${RED}✗ Please enter a name or exit with Ctrl+C.${REVERT}\n";
    elif test `echo "${username}" | grep -o "[^a-zA-Z]" | wc -l` -ne 0; then
      $echo "\t${RED}✗ Use only letter next time.${REVERT}\n";
    elif test `cat /etc/passwd | grep -e ^${username}:.\* | wc -l` -gt 0; then
      $echo "\t${RED}✗ User ${username} already exists.${REVERT}\n";
    else
      break
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter password:${REVERT} "
    read -s password

    if [ ! "${password}" ]; then
      $echo "\n\t${RED}✗ Password must be not empty${REVERT}\n";
    else
      password=$(perl -e 'print crypt($ARGV[0], "password")' $password)
      $echo "\n"
      break;
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter your first and last name:${REVERT} "
    read adminUserGitname

    if [ ! "${adminUserGitname}" ]; then
      $echo "\t${RED}✗ Name must be not empty${REVERT}\n";
    else
      break;
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter your email:${REVERT} "
    read useremail

    if [ ! "${useremail}" ]; then
      $echo "\t${RED}✗ Email must not be empty${REVERT}\n";
    elif test `echo "${useremail}" | grep -o ".*@.*\..*" | wc -l` -ne 1; then
      $echo "\t${RED}✗ Invalid email address.${REVERT}\n";
    else
      break;
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter SSH key passphrase (optional):${REVERT} "
    read sshPassphrase
    break;
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter SSH key comment [${BLUE}${useremail}${YELLOW}]${REVERT}: "
    read sshComment

    if [ ! "${sshComment}" ]; then
      sshComment=${useremail}
    fi

    break
  done
}



function collectDeployUserInfo(){
  repoHosting=''

  while true; do
    $echo "\t${YELLOW}➜ Enter username for deployment user [${CYAN}nodejs${YELLOW}]${REVERT}${REVERT} "
    read deployUsername

    if [ ! "${deployUsername}" ]; then
      if test `cat /etc/passwd | grep -e ^nodejs:.\* | wc -l` -gt 0; then
        $echo "\t${RED}✗ User ${deployUsername} already exists.${REVERT}\n";
      else
        deployUsername='nodejs'
        break;
      fi
    else
      if test `cat /etc/passwd | grep -e ^${deployUsername}:.\* | wc -l` -gt 0; then
        $echo "\t${RED}✗ User ${deployUsername} already exists.${REVERT}\n";
      else
        break;
      fi
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter password:${REVERT} "
    read -s deployPassword

    if [ ! "${deployPassword}" ]; then
      $echo "\n\t${RED}✗ Password must be not empty${REVERT}\n";
    else
      deployPassword=$(perl -e 'print crypt($ARGV[0], "password")' $deployPassword)
      $echo "\n"
      break;
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter first and last name for deploy user:${REVERT} "
    read deployUserGitname

    if [ ! "${deployUserGitname}" ]; then
      $echo "\t${RED}✗ Name must be not empty${REVERT}\n";
    else
      break;
    fi
  done

# while true; do
#   $echo "\t${YELLOW}➜ Enter email for deploy user:${REVERT} "
#   read deployEmail
#
#   if [ ! "${deployEmail}" ]; then
#     deployEmail=''
#   else
#     break;
#   fi
# done

  while true; do
    $echo "\t${YELLOW}➜ Do you want to deploy a repository? ${no}${REVERT}:${REVERT} "
    read yn
    case ${yn} in
      [Nn]* ) doDeployRepo=0; deployRepoUrl=''; ;;
      * ) doDeployRepo=1; break;;
    esac
    break
  done

  if test ${doDeployRepo} -eq 1; then
    while true; do
      $echo "\t${YELLOW}➜ Enter ${CYAN}SSH${YELLOW} repository URI (git@...):${REVERT}\n\t\t"
      read deployRepoUrl

      if [ ! $deployRepoUrl ]; then
        $echo "\t${RED}✗ Repository URI cannot be empty.${REVERT}\n";
      else
        if test `echo ${deployRepoUrl} | grep -o 'github.com' | wc -l` -eq 1; then
          repoHosting='github'
          collectGithubDeployInfo
          break
        elif test `echo ${deployRepoUrl} | grep -o 'bitbucket.org' | wc -l` -eq 1; then
          repoHosting='bitbucket'
          collectBitbucketDeployInfo
          break
        fi
      fi
    done
  fi
}



function collectGithubInfo(){
  while true; do
      $echo "\t${YELLOW}➜ Enter your Github username:${REVERT} "
      read githubusername

      if [ ! "${githubusername}" ]; then
        $echo "\t${RED}✗ Username must be not empty.${REVERT}\n";
      else
        break;
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter your Github password:${REVERT} "
      read -s githubpassword

      if [ ! "${githubpassword}" ]; then
        $echo "\n\t${RED}✗ Password must be not empty.${REVERT}\n";
      else
        break;
      fi
  done

# while true; do
#     $echo "\n\t${YELLOW}➜ Enter your Github access token:${REVERT} "
#     read githubToken
#
#     if [ ! "${githubToken}" ]; then
#       $echo "\t${RED}✗ Token must be not empty${REVERT}\n";
#     else
#       break;
#     fi
# done
}



function collectGithubDeployInfo(){
  while true; do
      $echo "\t${YELLOW}➜ Enter Github account name that has admin access to deploy repo:${REVERT} "
      read githubDeployAdminName

      if [ ! "${githubDeployAdminName}" ]; then
        $echo "\t${RED}✗ Account name must be not empty.${REVERT}\n";
      else
        break;
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter password for Github account ${BLUE}${githubDeployAdminName}${YELLOW}:${REVERT} "
      read -s githubDeployAdminPassword

      if [ ! "${githubDeployAdminPassword}" ]; then
        $echo "\n\t${RED}✗ Password must be not empty.${REVERT}\n";
      else
        break;
      fi
  done
}



function collectBitbucketInfo(){
  while true; do
    $echo "\t${YELLOW}➜ Enter your Bitbucket username:${REVERT} "
    read bbusername

    if [ ! "${bbusername}" ]; then
      $echo "\t${RED}✗ Username must be not empty${REVERT}\n";
    else
      break;
    fi
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter your Bitbucket password:${REVERT} "
    read -s bbpassword

    if [ ! "${bbpassword}" ]; then
      $echo "\n\t${RED}✗ Password must be not empty${REVERT}\n";
    else
      break;
    fi
  done
}


function collectBitbucketDeployInfo(){
  while true; do
      $echo "\t${YELLOW}➜ Enter Bitbucket account name that has read-only access to deploy repo:${REVERT} "
      read bitbucketDeployName

      if [ ! "${bitbucketDeployName}" ]; then
        $echo "\t${RED}✗ Account name must be not empty.${REVERT}\n";
      else
        break;
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter password for Bitbucket account ${BLUE}${bitbucketDeployName}${YELLOW}:${REVERT} "
      read -s bitbucketDeployPassword

      if [ ! "${bitbucketDeployPassword}" ]; then
        $echo "\n\t${RED}✗ Password must be not empty.${REVERT}\n";
      else
        $echo "\n"
        break;
      fi
  done
}


function collectNodeInfo(){
  while true; do
      $echo "\t${YELLOW}➜ Enter a value for NODE_ENV environment variable for this system [${CYAN}development${YELLOW}]: ${REVERT} "
      read nodeEnv

      if [ ! ${nodeEnv} ]; then
        nodeEnv='development';
        break;
      else
        break;
      fi
  done
}



function collectNodeInitScriptInfo(){
  while true; do
      $echo "\t${YELLOW}➜ Enter service name (app name):${REVERT} "
      read __initScriptName

      if [ ! "${__initScriptName}" ]; then
        $echo "\t${RED}✗ Service name must be not empty.${REVERT}\n";
      elif [ -x /etc/init.d/${__initScriptName} ]; then
        $echo "\t${RED}✗ Service with this name already exists. Overwrite? ${no}${REVERT} ";
        read yn

        case ${yn} in
          [Yy]* ) initScriptName=$__initScriptName; break;;
          * ) ;;
        esac

      else
        initScriptName=$__initScriptName
        break;
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter short service description (optional):${REVERT} "
      read initScriptDesc

      if [ ! "${initScriptDesc}" ]; then
        initScriptDesc='Node app service'
        break
      else
        break
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter path to application ${CYAN}root${YELLOW} directory:${REVERT} "
      read appDir

      if [ ! "${appDir}" ]; then
        $echo "\t${RED}✗ Path must be not empty.${REVERT}\n";
      else
        break;
      fi
  done

  while true; do
      $echo "\t${YELLOW}➜ Enter path to main .js file:${REVERT} "
      read appPath

      if [ ! "${appPath}" ]; then
        $echo "\t${RED}✗ Path must be not empty.${REVERT}\n";
      else
        break;
      fi
  done
}



function collectRedisInfo(){
  local defaultRedisDbPath=/usr/local/var/lib/redis
  local defaultRedisDbName=redis.rdb
  local defaultRedisBind=127.0.0.1
  local defaultRedisPort=6379

  while true; do
    $echo "\t${YELLOW}➜ Enter interface to listen on [${BLUE}127.0.0.1${YELLOW}]${REVERT}${REVERT} "
    read redisBind

    if [ ! "${redisBind}" ]; then
      redisBind=${defaultRedisBind}
    fi

    break
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter port to listen on [${BLUE}6379${YELLOW}]${REVERT}:${REVERT} "
    read redisPort

    if [ ! "${redisPort}" ]; then
      redisPort=${defaultRedisPort}
    fi

    break
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter path for Redis database [${BLUE}/usr/local/var/lib/redis${YELLOW}]${REVERT}:${REVERT} "
    read redisDbPath

    if [ ! "${redisDbPath}" ]; then
      redisDbPath=${defaultRedisDbPath}
    fi

    break
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter name for Redis database file [${BLUE}redis-${redisPort}.rdb${YELLOW}]${REVERT}:${REVERT} "
    read redisDbName

    if [ ! "${redisDbName}" ]; then
      redisDbName=${defaultRedisDbName}
    fi

    break
  done
}


function collectCouchDBInfo(){
  local defaultCouchdbBind=127.0.0.1
  local defaultCouchdbPort=5984

  while true; do
    $echo "\t${YELLOW}➜ Enter interface to listen on [${BLUE}127.0.0.1${YELLOW}]${REVERT}:${REVERT} "
    read couchdbBind

    if [ ! "${couchdbBind}" ]; then
      couchdbBind=${defaultCouchdbBind}
    fi

    break
  done

  while true; do
    $echo "\t${YELLOW}➜ Enter port to listen on [${BLUE}5984${YELLOW}]${REVERT}:${REVERT} "
    read couchdbPort

    if [ ! "${couchdbPort}" ]; then
      couchdbPort=${defaultCouchdbPort}
    fi

    break
  done

  while true; do
    $echo "\t${YELLOW}➜ Enable authentication? [${BLUE}Y${YELLOW}/n]${REVERT}:${REVERT} "
    read yn
    case ${yn} in
      [Nn]* ) couchdbAuth=0; break;;
      * ) couchdbAuth=1; break;;
    esac
    break
  done

  if test ${couchdbAuth} -eq 1; then
    while true; do
      $echo "\t${YELLOW}➜ Enter admin username:${REVERT} "
      read couchdbUser

      if [ ! "${couchdbUser}" ]; then
        $echo "\t${RED}✗ Username must be not empty${REVERT}\n";
      else
        break;
      fi
    done

    while true; do
      $echo "\t${YELLOW}➜ Enter admin password:${REVERT} "
      read couchdbPass

      if [ ! "${couchdbPass}" ]; then
        $echo "\t${RED}✗ Password must be not empty${REVERT}\n";
      else
        break;
      fi
    done
  fi
}



function collectMonitInfo(){
  if test $doNodeInitScript -eq 0; then
    while true; do
        $echo "\t${YELLOW}➜ Enter service name to monitor (in /etc/init.d):${REVERT} "
        read SERVICE_NAME

        if [ ! "${SERVICE_NAME}" ]; then
          $echo "\t${RED}✗ Service name must be not empty.${REVERT}\n";
        else
          break;
        fi
    done
  else
    SERVICE_NAME=$initScriptName
  fi

  while true; do
      $echo "\t${YELLOW}➜ Enter email that will receive alerts:${REVERT} "
      read SYSADMIN_EMAIL

      if [ ! "${SYSADMIN_EMAIL}" ]; then
        $echo "\t${RED}✗ Email must be not empty.${REVERT}\n";
      else
        break;
      fi
  done
}



######## ##     ## ##    ##  ######  ######## ####  #######  ##    ##  ######
##       ##     ## ###   ## ##    ##    ##     ##  ##     ## ###   ## ##    ##
##       ##     ## ####  ## ##          ##     ##  ##     ## ####  ## ##
######   ##     ## ## ## ## ##          ##     ##  ##     ## ## ## ##  ######
##       ##     ## ##  #### ##          ##     ##  ##     ## ##  ####       ##
##       ##     ## ##   ### ##    ##    ##     ##  ##     ## ##   ### ##    ##
##        #######  ##    ##  ######     ##    ####  #######  ##    ##  ######





function installPrerequisites(){
  $echo "\n${BLUE}● Updating package caches...${REVERT}\n"
  apt-get -qq update

  $echo "\n${BLUE}● Installing prerequisites... This may take a while, so don't interrupt it.${REVERT}\n"
  apt-get -qqy install build-essential libssl-dev git-core vim rake atop saidar curl authbind exiv2
}







# create sudoer user
function createUser() {
  $echo "\n${GREEN}● Creating new user ${username}.${REVERT}\n"
  groupadd admin 1>/dev/null 2>&1
  useradd -m -d /home/${username} -G admin,sudo,www-data -p ${password} ${username} 1>/dev/null 2>&1
  addSudoersGroup 'admin'
}







function addSudoersGroup(){
  local groupname=$1

  if [ ! ${groupname} ]; then
    $echo "\t${RED}✗ Need group name.${REVERT}\n"
  else
    local exists=`sudo cat /etc/sudoers | grep -e ^%${groupname} | wc -l`

    if test ${exists} -eq 0; then
      echo "%${groupname} ALL=(ALL) ALL" >> /etc/sudoers
    else
      $echo "\t${GREEN}✓ Group ${groupname} already in sudoers.${REVERT}\n";
    fi
  fi

}






function addDeployUserPermissions(){
  if [ ! ${deployUsername} ]; then
    $echo "\t${RED}✗ Need username.${REVERT}\n"
  else
    local exists=`sudo cat /etc/sudoers | grep -e ^${deployUsername} | wc -l`

    if test ${exists} -eq 0; then
      echo "${deployUsername} ALL = NOPASSWD: /etc/init.d/nodeapp, /bin/kill, /usr/local/bin/npm" >> /etc/sudoers
    else
      $echo "\t${GREEN}✓ User ${deployUsername} already in sudoers.${REVERT}\n";
    fi
  fi
}








#### SSH key generation, takes user name and email address ####
function generateSshKey(){
  local username=$1;
  local sshComment=$2;
  local homedir=`awk -F: -v v="${username}" '{if ($1==v) print $6}' /etc/passwd`

  $echo "\n${GREEN}● Generating SSH key with comment ${sshComment}${REVERT}\n"

  sudo -u ${username} ssh-keygen -q -t rsa -C "${sshComment}" -P "${sshPassphrase}" -f ${homedir}/.ssh/id_rsa

  $echo "\n${GREEN}✓ Generated SSH key for user ${username}.${REVERT}\n";
}








#### Git setup ####
function setupGit() {
  local username=$1;
  local useremail=$2;
  local homedir=$3;
  local gitname=$4;

  sudo -u ${username} git config -f ${homedir}/.gitconfig user.name "${gitname}"
  sudo -u ${username} git config -f ${homedir}/.gitconfig user.email "${useremail}"
  sudo -u ${username} git config -f ${homedir}/.gitconfig color.ui true
}






#### Github setup ####
function setupGithub(){
  local username=$1;

  sudo -u ${username} git config -f /home/${username}/.gitconfig github.user "${githubusername}"
  #sudo -u ${username} git config -f /home/${username}/.gitconfig github.token "${githubToken}"

  local homedir=`awk -F: -v v="${username}" '{if ($1==v) print $6}' /etc/passwd`
  local sshkey="`cat ${homedir}/.ssh/id_rsa.pub`"
  local label="`hostname` `ifconfig eth0 | grep -o -m 1 '\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)' | head -n 1` `date +'%b %e %Y, %X'`"

  # add machine SSH key to github account
  local res=`curl -s -i -X POST -u "${githubusername}:${githubpassword}" https://api.github.com/user/keys -d '{"key": "'"${sshkey}"'", "title":"'"${label}"'"}' -H 'content-type: application/json' | grep HTTP/1.1 | awk {'print $2'}`

  case $res in
    201* ) $echo "\n${YELLOW}✓ Added SSH key to ${BLUE}Github${YELLOW} account ${BLUE}${githubusername}${YELLOW}.${REVERT}\n"; ;;
    * ) $echo "\n${RED}✗ Failed to add SSH key: HTTP status code ${res} (look it up).${REVERT}"; ;;
  esac

  $echo "\n${GREEN}✓ Done setting up Github.${REVERT}\n"
}




#### Github deployment setup ####
function setupGithubDeploy(){
  local deployUsername=$1;
  local deployRepo=$2;

  local homedir=`awk -F: -v v="${deployUsername}" '{if ($1==v) print $6}' /etc/passwd`
  local sshkey="`cat ${homedir}/.ssh/id_rsa.pub`"
  local label="`hostname` `ifconfig eth0 | grep -o -m 1 '\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)' | head -n 1` `date +'%b %e %Y, %X'`"

  # add deploy SSH key to github repo
  local res=`curl -s -i -X POST -u "${githubDeployAdminName}:${githubDeployAdminPassword}" https://api.github.com/repos/${deployRepo}/keys -d '{"key": "'"${sshkey}"'", "title":"'"${label}"'"}' -H 'content-type: application/json' | grep HTTP/1.1 | awk {'print $2'}`

  case $res in
    201* ) $echo "\n${YELLOW}✓ Added SSH key to ${BLUE}Github${YELLOW} repo ${BLUE}${deployRepo}${YELLOW}.${REVERT}\n"; ;;
    * ) $echo "\n${RED}✗ Failed to add SSH key: HTTP status code ${res} (look it up).${REVERT}"; ;;
  esac

  $echo "\n${GREEN}✓ Done setting up Github.${REVERT}\n"
}




#### Bitbucket setup ####
function setupBitbucket(){
  local username=$1;

  if [ $2 ]; then
    bbusername=$2;
  fi

  if [ $3 ]; then
    bbpassword=$3;
  fi

  local homedir=`awk -F: -v v="${username}" '{if ($1==v) print $6}' /etc/passwd`
  local sshkey="`cat ${homedir}/.ssh/id_rsa.pub`"
  local label="`hostname` `ifconfig eth0 | grep -o -m 1 '\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)' | head -n 1` `date +'%b %e %Y, %X'`"

  local res=`curl -s -i -X POST --user "${bbusername}":"${bbpassword}" https://api.bitbucket.org/1.0/ssh-keys/ --data-urlencode key="${sshkey}" --data-urlencode label="${label}" | grep HTTP/1.1 | awk {'print $2'}`

  case $res in
    200* ) $echo "\n${YELLOW}✓ Added SSH key to ${BLUE}Bitbucket${YELLOW} account ${BLUE}${bbusername}${YELLOW}.${REVERT}\n"; ;;
    400* ) $echo "\n${RED}✗ Failed to add SSH key: invalid key or key already registered.${REVERT}\n"; ;;
    401* ) $echo "\n${RED}✗ Failed to add SSH key: unauthorized (invalid credentials).${REVERT}\n"; ;;
    * ) $echo "\n${RED}✗ Failed to add SSH key: unspecified error.${REVERT}\n"; ;;
  esac

  $echo "\n${GREEN}✓ Done setting up Bitbucket.${REVERT}\n"
}







#### NodeJS installation ####
function installNode(){
  $echo "\n${GREEN}● Building and installing NodeJS.${REVERT}\n"

  [ $1 ] && srcpath=$1 || srcpath=''

  if [[ ${username} == '' || ${username} == root ]]; then
    local username='root'
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath='/usr/local/src/node'
  else
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath="/home/${username}/distr/node"
  fi

  $echo "\n${GREEN}● Most recent stable version of Node is...${REVERT} "

  local latest=v`curl -s https://api.github.com/repos/joyent/node/git/refs/tags | grep -oe "[0-9]*\.[0-9]*\.[0-9]*" | uniq | awk '
  {
    if (max==""){
      max=$1
    };

    split($1, tag, ".");
    split(max, current, ".");

    if( (tag[2] % 2) == 0 ){

      if( tag[1] > current[1] ){
        max=$1
      };

      if( tag[2] > current[2] ){
        max=$1
      };

      if( (tag[3] > current[3])) {
        max=$1
      };

    };
  }
  END {print max}
  '`

  $echo "${CYAN}${latest}${REVERT}\n"

  # if destination dir exists - go there and see if it's a node git repo
  if [ -d ${srcpath} ]; then
    cd ${srcpath}

    if test `git remote show origin | grep -o joyent/node | wc -l` -eq 0; then
      while true; do
        $echo "\t${RED}➜ Destination directory '"${srcpath}"' exists and is not a NodeJS repo.${REVERT}\n"
        $echo "\t${RED}  Enter new destination or remove '"${srcpath}"' manually and press ${BLUE}ENTER${GREEN}: ${REVERT} "
        read srcpath

        cd /
        installNode ${srcpath}
        break
      done
    else
      cd ${srcpath}

      sudo -u ${username} make clean
      sudo -u ${username} git fetch
    fi
  else
    sudo -u $username mkdir -p ${srcpath}
    sudo -u $username git clone https://github.com/joyent/node.git ${srcpath}
  fi

  cd ${srcpath}

  sudo -u ${username} git checkout ${latest}
  sudo -u ${username} ./configure && sudo -u ${username} make
  make install

  sudo -u ${username} $echo "NODE_ENV=${nodeEnv}\n" >> /etc/environment

  if [ ! ${username} = 'root' ]; then
    sudo -u ${username} $echo "export NODE_ENV=${nodeEnv}\n" >> /home/${username}/.bashrc
  fi

  $echo "\n${GREEN}✓ Done setting up NodeJS.${REVERT}\n"
}





#### Install Node utilities ####
function installNodeTools(){
  $echo "\n${GREEN}● Installing Node utilities.${REVERT}\n"

  npm -g install forever vows supervisor jscoverage

  $echo "\n${GREEN}✓ Done installing Node utilities.${REVERT}\n"
}





#### Install Node utilities ####
function installJscoverage(){
  $echo "\n${GREEN}● Installing Node JSCoverage.${REVERT}\n"

  [ $1 ] && srcpath=$1 || srcpath=''

  if [[ ${username} == '' || ${username} == root ]]; then
    local username='root'
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath='/usr/local/src/node-jscoverage'
  else
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath="/home/${username}/distr/node-jscoverage"
  fi

  git clone https://github.com/visionmedia/node-jscoverage.git ${srcpath}

  cd ${srcpath}

  ./configure && make && make install

  $echo "\n${GREEN}✓ Done installing Node JSCoverage.${REVERT}\n"
}




#### Create init.d script for running node app as service ####
function createNodeInitScript(){
  $echo "\n${GREEN}● Writing Node init script.${REVERT}\n"

  local NODE=`which node`

  touch /etc/init.d/nodeapp
  chmod +x /etc/init.d/nodeapp

  cat <<EOF > /etc/init.d/nodeapp
#!/bin/bash

### BEGIN INIT INFO
# Provides:          $initScriptName
# Required-Start:    \$local_fs \$syslog \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       $initScriptDesc
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
NODE=$NODE
APP_DIR=$appDir
APP_PATH=$appPath
APP_NAME=$initScriptName

test -x \$NODE || exit 0

function start_app {
  if [ ! -f \$APP_DIR/pids/\$APP_NAME.pid ]; then
    NODE_ENV=\$nodeEnv nohup \$NODE \$APP_PATH 1>>\$APP_DIR/logs/\$APP_NAME.log 2>&1 &
    echo \$! > \$APP_DIR/pids/\$APP_NAME.pid
  else
    echo "Process already running with PID \`cat \$APP_DIR/pids/\$APP_NAME.pid\`"
    echo "PID file is '\$APP_DIR/pids/\$APP_NAME.pid'"
  fi
}

function stop_app {
  kill -1 \`cat \$APP_DIR/pids/\$APP_NAME.pid\`
  rm \$APP_DIR/pids/\$APP_NAME.pid
}

case \$1 in
   start)
      start_app ;;
    stop)
      stop_app ;;
    restart)
      stop_app
      start_app
      ;;
    *)
      echo "usage: \$APP_NAME {start|stop|restart}" ;;
esac
exit 0
EOF

  $echo "\n${GREEN}✓ Done Node configuring init service.${REVERT}\n"
}






#### CouchDB setup ####
function installCouchDB(){
  $echo "\n${GREEN}● Building and installing CouchDB.${REVERT}\n\n"

  [ $1 ] && srcpath=$1 || srcpath=''

  if [[ ${username} == '' || ${username} == root ]]; then
    local username='root'
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath='/usr/local/src/build-couchdb'
  else
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath="/home/${username}/distr/build-couchdb"
  fi

  sudo apt-get -qqy install make gcc zlib1g-dev libssl-dev rake

  sudo groupadd couchdb 1>/dev/null 2>&1
  sudo useradd -d /usr/local/var/lib/couchdb -g couchdb couchdb 1>/dev/null 2>&1

  # if destination dir exists - go there and see if it's a node git repo
  if [ -d ${srcpath} ]; then
    cd ${srcpath}

    if test `git remote show origin | grep -o iriscouch/build-couchdb | wc -l` -eq 0; then
      while true; do
        $echo "\t${RED}➜ Destination directory '"${srcpath}"' exists and is not a CouchDB repo.${REVERT}\n"
        $echo "\t${RED}  Enter new destination or remove '"${srcpath}"' manually and press ${BLUE}ENTER${GREEN}: ${REVERT} "
        read srcpath

        cd /
        installCouchDB ${srcpath}
        break
      done
    else
      cd ${srcpath}

      sudo -u ${username} git fetch
      sudo -u ${username} git reset --hard HEAD
    fi
  else
    sudo -u $username mkdir -p ${srcpath}
    sudo -u $username git clone https://github.com/iriscouch/build-couchdb.git ${srcpath}
    sudo -u ${username} git submodule init
    sudo -u ${username} git submodule update
  fi

  cd ${srcpath}

  rake install=/usr/local/var/lib/couchdb

  touch /etc/init/couchdb.conf

  local couchdbconf="
# Upstart file at /etc/init/couchdb.conf
# CouchDB

start on runlevel [2345]
stop on runlevel [06]

pre-start script
  chown -R couchdb /usr/local/var/lib/couchdb
end script

script
  exec sudo -E -u couchdb /usr/local/var/lib/couchdb/bin/couchdb
end script

respawn
respawn limit 10 5
"

  # edit couchdb conf file
  sed -i -e "s/^\([\s|;]*bind_address\s.*\)/bind_address ${couchdbBind}/g" /usr/local/var/lib/couchdb/etc/couchdb/local.ini
  sed -i -e "s/^\([\s|;]*port\s.*\)/port ${couchdbPort}/g" /usr/local/var/lib/couchdb/etc/couchdb/local.ini

  if [[ ${couchdbUser} != '' && ${couchdbPass} != '' ]]; then
    sed -i -e "s/^\([\s|;]*\)\(WWW-Authenticate\s.*\)/\2/g" /usr/local/var/lib/couchdb/etc/couchdb/local.ini
    sed -i -e "s/^\([\s|;]*require_valid_user\s.*\)/require_valid_user = true/g" /usr/local/var/lib/couchdb/etc/couchdb/local.ini
    sed -i -e "s/^\([\s|;]*\)\(\[admins\]\)/\2/g" /usr/local/var/lib/couchdb/etc/couchdb/local.ini
    sed -i -e "/^\([\s|;]*\)\(\[admins\]\)/a\\"${couchdbUser}" = "${couchdbPass} /usr/local/var/lib/couchdb/etc/couchdb/local.ini
  fi

  $echo "\n${BLUE}● CouchDB configuration file is /usr/local/var/lib/couchdb/etc/couchdb/local.ini${REVERT}\n"
  $echo "${couchdbconf}" > /etc/init/couchdb.conf;

  if test `ps ax | grep couchdb | grep -v grep | wc -l` -gt 0; then
    service couchdb restart
  else
    service couchdb start
  fi

  $echo "\n${GREEN}✓ Done setting up CouchDB.${REVERT}\n"
}







#### MongoDB setup ####
function installMongoDB(){
  $echo "\n${GREEN}● Installing MongoDB.${REVERT}\n"

  apt-key adv --keyserver keyserver.ubuntu.com --recv 7F0CEB10
  $echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen' >> /etc/apt/sources.list

  apt-get -qqy update
  apt-get -qqy install mongodb-10gen

  $echo "\n${GREEN}✓ Done setting up MongoDB.${REVERT}\n"
}







#### Redis setup ####
function installRedis(){
  $echo "\n${GREEN}● Installing Redis.${REVERT}\n"

  [ $1 ] && srcpath=$1 || srcpath=''

  $echo "\n${GREEN}● Most recent stable version of Redis is...${REVERT} "

  local latest=`curl -s https://api.github.com/repos/antirez/redis/git/refs/tags | grep -oe "[0-9]*\.[0-9]*\.[0-9]*" | uniq | awk '
  {
    if (max==""){
      max=$1
    };

    split($1, tag, ".");
    split(max, current, ".");

    if( (tag[2] % 2) == 0 ){

      if( tag[1] > current[1] ){
        max=$1
      };

      if( tag[2] > current[2] ){
        max=$1
      };

      if( (tag[3] > current[3])) {
        max=$1
      };

    };
  }
  END {print max}
  '`

  $echo "${CYAN}${latest}${REVERT}\n"

  if [[ ${username} == '' || ${username} == root ]]; then
    local username='root'
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath='/usr/local/src/redis'
  else
    [ ${srcpath} ] && srcpath=${srcpath} || srcpath="/home/${username}/distr/redis"
  fi

  # if destination dir exists - go there and see if it's a node git repo
  if [ -d ${srcpath} ]; then
    cd ${srcpath}

    if test `git remote show origin | grep -o antirez/redis | wc -l` -eq 0; then
      while true; do
        $echo "\t${RED}➜ Destination directory '"${srcpath}"' exists and is not a Redis repo.${REVERT}\n"
        $echo "\t${RED}  Enter new destination or remove '"${srcpath}"' manually and press ${BLUE}ENTER${GREEN}: ${REVERT} "
        read srcpath

        cd /
        installRedis ${srcpath}
        break
      done
    else
      cd ${srcpath}

      sudo -u ${username} make clean
      sudo -u ${username} git fetch
    fi
  else
    sudo -u $username mkdir -p ${srcpath}
    sudo -u $username git clone https://github.com/antirez/redis.git ${srcpath}
  fi

  cd ${srcpath}

  sudo -u ${username} git checkout ${latest}

  sudo -u ${username} make
  make install

  mkdir /etc/redis
  cp ${srcpath}/redis.conf /etc/redis/redis-${redisPort}.conf

  mkdir -p ${redisDbPath}

  # edit redis conf file
  sed -i -e 's/^\([\s|#]*bind\s.*\)/bind '${redisBind}'/g'  /etc/redis/redis-${redisPort}.conf #set bind directive
  sed -i -e 's/^\([\s|#]*port\s.*\)/port '${redisPort}'/g'  /etc/redis/redis-${redisPort}.conf #set port directive
  sed -i -e 's_^\([\s|#]*dir\s.*\)_dir '${redisDbPath}'_g'  /etc/redis/redis-${redisPort}.conf #set dir directive
  sed -i -e 's/^\([\s|#]*dbfilename\s.*\)/dbfilename '${redisDbName}'/g'  /etc/redis/redis-${redisPort}.conf #set dbfilename directive

  $echo "\n${BLUE}● Redis configuration file is /etc/redis/redis-${redisPort}.conf${REVERT}\n"

  touch /etc/init/redis-${redisPort}.conf

  local redisconf="
# Upstart file at /etc/init/redis-${redisPort}.conf
# Redis

description 'redis server at port ${redisPort}'

start on runlevel [2345]
stop on shutdown

exec /usr/local/bin/redis-server /etc/redis/redis-${redisPort}.conf

respawn
"

  $echo "${redisconf}" > /etc/init/redis-${redisPort}.conf;

  service redis-${redisPort} start

  $echo "\n${GREEN}✓ Done setting up Redis at port ${redisPort}.${REVERT}\n"
}





function installMonit(){
  $echo "\n${GREEN}● Installing Monit.${REVERT}\n"

  local HOST_NAME=`hostname`

  apt-get install monit

  # configure

  # set service check interval
  sed -i -e 's/\(.*\)\(set daemon \)\(\s*[0-9]*\s*\)\(.*\)/  \2 60  \4/g' /etc/monit/monitrc

  # set startup check delay
  sed -i -e 's/\(.*\)\(with start delay \)\(\s*[0-9]*\s*\)\(.*\)/  \2 120  \4/g' /etc/monit/monitrc

  # set mailserver to localhost
  sed -i -e 's/\(.*\)\(set mailserver \)\([ *|a-zA-Z|0-9|\.,]*\)\(#.*\)/  \2 localhost     \4/g' /etc/monit/monitrc

  # set logging
  sed -i -e 's/\(.*\)\(set logfile .*\)/  \2/g' /etc/monit/monitrc

  # set email from which to send alerts
  sed -i -e "s/\(.*\)\(set mail-format \)\(.*\)/  \2 { from: monit@$HOST_NAME }/g" /etc/monit/monitrc

  # set email to receive all alerts
  sed -i -e "0,/set alert/s/\(.*\)\(set alert \)\(.*\)/  \2$SYSADMIN_EMAIL/" /etc/monit/monitrc

cat <<EOF >> /etc/monit/monitrc

check host $HOST_NAME with address `curl -s whatismyip.org`
    start program = "/etc/init.d/$SERVICE_NAME start"
    stop program  = "/etc/init.d/$SERVICE_NAME stop"
    if failed port 80 protocol HTTP
        request /
        with timeout 10 seconds
        then restart

EOF

  # enable monit service
  sed -i -e 's/\(startup=\)\(.*\)/\11/' /etc/default/monit

  service monit start

  $echo "\n${GREEN}✓ Monit installed.${REVERT}\n"
}





#### Create user nodejs with homedir in /var/www and group www-data ####
function createLimitedUser(){
  local homedir='/home/'${deployUsername}

  $echo "\n${GREEN}● Creating production user '"${deployUsername}"'.${REVERT}\n"

  groupadd www-data 1>/dev/null 2>&1
  useradd -m -d "${homedir}" -G www-data -p ${deployPassword} ${deployUsername} 1>/dev/null 2>&1

  #chown ${deployUsername}:www-data -R "${homedir}"
  mkdir -p /var/www 1>/dev/null 2>&1
  chown ${deployUsername}:www-data -R /var/www

  installZsh ${deployUsername} "${homedir}"
  generateSshKey ${deployUsername} "${deployUsername}"
  setupGit ${deployUsername} ${deployUsername} "${homedir}" ${deployUserGitname};

  if [ $repoHosting ]; then
    repoPath=`echo ${deployRepoUrl} | grep -oe '[a-zA-Z0-9_\-]*\/[a-zA-Z0-9_\-]*\.git$' | grep -oe '[a-zA-Z0-9_\-]*\/[a-zA-Z0-9_\-]*'`
    repoName=`echo ${repoPath} | grep -oe '[a-zA-Z0-9_\-]*$'`
    sudo -u ${deployUsername} touch ${homedir}/.ssh/known_hosts
    sudo -u ${deployUsername} ssh-keyscan -t rsa,dsa github.com 2>&1 | sort -u - ${homedir}/.ssh/known_hosts > ${homedir}/.ssh/tmp_hosts
    sudo -u ${deployUsername} cat ${homedir}/.ssh/tmp_hosts > ${homedir}/.ssh/known_hosts
    sudo -u ${deployUsername} ssh-keyscan -t rsa,dsa bitbucket.org 2>&1 | sort -u - ${homedir}/.ssh/known_hosts > ${homedir}/.ssh/tmp_hosts
    sudo -u ${deployUsername} cat ${homedir}/.ssh/tmp_hosts > ${homedir}/.ssh/known_hosts
    sudo -u ${deployUsername} chmod 0600 ${homedir}/.ssh/known_hosts
    rm ${homedir}/.ssh/tmp_hosts
  fi

  if [[ $repoHosting == 'github' ]]; then
    setupGithubDeploy ${deployUsername} ${repoPath}
    sudo -u ${deployUsername} git clone ${deployRepoUrl} /var/www/${repoName}
    sudo -u ${deployUsername} chown ${deployUsername}:www-data -R /var/www/${repoName}
  fi

  if [[ $repoHosting == 'bitbucket' ]]; then
    setupBitbucket ${deployUsername} ${bitbucketDeployName} ${bitbucketDeployPassword}
    sudo -u ${deployUsername} git clone ${deployRepoUrl} /var/www/${repoName}
    sudo -u ${deployUsername} chown ${deployUsername}:www-data -R /var/www/${repoName}
  fi

  addDeployUserPermissions

  $echo "\n${GREEN}✓ Done creating user '"${deployUsername}"'.${REVERT}\n"
}







#### Install Z Shell and clones oh-my-zshell into homedir ####
function installZsh(){
  local user=$1
  local homedir=$2
  $echo "\n${GREEN}● Installing Z Shell and oh-my-zshell.${REVERT}\n\n"

  if [ ! -x /bin/zsh ]; then
    apt-get -qqy install zsh
  fi

  if [ ! -d ${homedir}/.oh-my-zsh ]; then
    sudo -u "${user}" git clone git://github.com/robbyrussell/oh-my-zsh.git ${homedir}/.oh-my-zsh
    sudo -u "${user}" cp ${homedir}/.oh-my-zsh/templates/zshrc.zsh-template ${homedir}/.zshrc

    chsh "${user}" -s `which zsh`

    sudo -u ${user} $echo "export NODE_ENV=${nodeEnv}\n" >> ${homedir}/.zshrc

    # fix ls parameters
    sed -i -e "s/^alias lsa=.*/alias lsa='ls -lah --group-directories-first'/" ${homedir}/.oh-my-zsh/lib/aliases.zsh
    sed -i -e "s/^alias l=.*/alias l='ls -la --group-directories-first'/" ${homedir}/.oh-my-zsh/lib/aliases.zsh
    sed -i -e "s/^alias ll=.*/alias ll='ls -l --group-directories-first'/" ${homedir}/.oh-my-zsh/lib/aliases.zsh

    cat <<EOF >> ${homedir}/.oh-my-zsh/lib/aliases.zsh
alias pulsh='git pull && git push'
alias gadd='git add .'
alias gits='git status'
alias afind='ack-grep -il'

function gcom() {git add . && git commit -m "\$@" ;}
function com() {git add . && git commit -am "\$@" && git pull && git push;}
EOF
  fi

  $echo "\n${GREEN}✓ Done setting up Z Shell and oh-my-zshell.${REVERT}"
}







#### Install Postfix ####
function installPostfix(){
  $echo "\n${GREEN}● Installing Postfix.${REVERT}\n"

  apt-get -qqy install postfix
  dpkg-reconfigure postfix

  $echo "\n${GREEN}✓ Done setting up Postfix.${REVERT}\n"
}





#### Setup authbind ####
function setupAuthbind(){
  $echo "\n${GREEN}● Configuring authbind.${REVERT}\n"

  touch /etc/authbind/byport/{80,443}
  chmod a+x /etc/authbind/byport/{80,443}

  $echo "\n${GREEN}✓ Done setting up authbind.${REVERT}\n"
}





function createNewUser(){
  createUser
  setupGit "${username}" "${useremail}" /home/${username} ${adminUserGitname}
  generateSshKey ${username} "${sshComment}"
  installZsh "${username}" "/home/${username}";
}





######## ########  ######  ########  ######
   ##    ##       ##    ##    ##    ##    ##
   ##    ##       ##          ##    ##
   ##    ######    ######     ##     ######
   ##    ##             ##    ##          ##
   ##    ##       ##    ##    ##    ##    ##
   ##    ########  ######     ##     ######
function isInstalled(){
  local program=$1

  if [ -f /usr/local/var/lib/${program}/bin/${program} ]; then
    return 0
  elif which ${program} > /dev/null; then
    return 0
  elif test `ps ax | grep ${program} | grep -v grep | wc -l` -gt 0; then
    return 0
  else
    return 1
  fi;
}



function checkInstalled(){
  local programs=( node couchdb redis mongod postfix  )

  $echo "\n${GREEN}● Checking for existing installations...${REVERT}"

  for prog in ${programs[@]}
  do
     isInstalled ${prog}
     if test $? -eq 0; then
       $echo "\n\t${CYAN}● ${prog} appears to be installed.${REVERT}"
     fi
     # other stuff on $name
  done

  $echo "\n${GREEN}✓ Done.${REVERT}\n"
}




 ######  ########    ###    ########  ########
##    ##    ##      ## ##   ##     ##    ##
##          ##     ##   ##  ##     ##    ##
 ######     ##    ##     ## ########     ##
      ##    ##    ######### ##   ##      ##
##    ##    ##    ##     ## ##    ##     ##
 ######     ##    ##     ## ##     ##    ##
clear
$echo "${GREEN}Environment setup script.${REVERT}\n"
checkInstalled
cQ=0
totalQuestions=11

function NN(){
  echo "$BLACK[$(($1))/$totalQuestions]$REVERT "
}




##     ## ######## ##    ## ##     ##
###   ### ##       ###   ## ##     ##
#### #### ##       ####  ## ##     ##
## ### ## ######   ## ## ## ##     ##
##     ## ##       ##  #### ##     ##
##     ## ##       ##   ### ##     ##
##     ## ######## ##    ##  #######
$echo "\n${WHITEBLUE}                      Options                       ${REVERT}\n"

cQ=$[cQ+1]
while true; do
    $echo "\n$(NN $cQ)${GREEN}● Do you want to create a new user for yourself (recommended)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doNewUser=1; collectAdminUserInfo; break;;
      * ) doNewUser=0; break;;
    esac
    break
done

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to create deployment user account (read-only repo access)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doLimitedUser=1; collectDeployUserInfo; break;;
      * ) doLimitedUser=0; break;;
    esac
    break
done
#currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to set up git for Github? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doGithub=1; collectGithubInfo; break;;
      * ) doGithub=0; break;;
    esac
    break
done
#currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to set up git for Bitbucket? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doBitbucket=1; collectBitbucketInfo; $echo "\n"; break;;
      * ) doBitbucket=0; break;;
    esac
    break
done
##currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install NodeJS (~8 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doNodeJS=1; collectNodeInfo; break;;
      * ) doNodeJS=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to run a node app as a service? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doNodeInitScript=1; collectNodeInitScriptInfo; break;;
      * ) doNodeInitScript=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install CouchDB (~25-35 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doCouchDB=1; collectCouchDBInfo; break;;
      * ) doCouchDB=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install MongoDB (~3 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doMongoDB=1; break;;
      * ) doMongoDB=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install Redis (~2 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doRedis=1; collectRedisInfo; break;;
      * ) doRedis=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install Postfix (email server) (~5 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doPostfix=1; break;;
      * ) doPostfix=0; break;;
    esac
    break
done
currentQuestion=$(($currentQuestion + 1))

cQ=$[cQ+1]
while true; do
    $echo "$(NN $cQ)${GREEN}● Do you want to install Monit (monitoring service) (~2 min)? ${no}${REVERT} "
    read yn
    case ${yn} in
      [Yy]* ) doMonit=1; collectMonitInfo; break;;
      * ) doMonit=0; break;;
    esac
    break
done


installPrerequisites


if test $doNewUser -eq 1; then
  createNewUser

  setupAuthbind

  if test $doGithub -eq 1; then
    setupGithub ${username}
  fi


  if test $doBitbucket -eq 1; then
    setupBitbucket "${username}"
  fi
fi


if test $doLimitedUser -eq 1; then
  createLimitedUser
fi


if test $doNodeJS -eq 1; then
  installNode
  installNodeTools
  installJscoverage
fi


if test $doNodeInitScript -eq 1; then
  createNodeInitScript
fi


if test $doCouchDB -eq 1; then
  installCouchDB
fi


if test $doMongoDB -eq 1; then
  installMongoDB
fi


if test $doRedis -eq 1; then
  installRedis
fi


if test $doMonit -eq 1; then
  installMonit
fi


if test $doPostfix -eq 1; then
  installPostfix
fi






######## ##    ## ########
##       ###   ## ##     ##
##       ####  ## ##     ##
######   ## ## ## ##     ##
##       ##  #### ##     ##
##       ##   ### ##     ##
######## ##    ## ########
$echo "\n${WHITEBLUE}"
$echo "                      SETUP COMPLETE                       "
$echo "${WHITEBLUE}${REVERT}\n"
if test $doNewUser -eq 1; then
  $echo "\n${GREEN}Your new account name is ${BLUE}${username}${REVERT}"
  $echo "\n${GREEN}Run ${BLUE}'cat /home/${username}/.ssh/id_rsa.pub'${REVERT} to display your public SSH key${GREEN}${REVERT}\n"
fi

if test $doLimitedUser -eq 1; then
  $echo "\n${GREEN}Deployment account name is ${BLUE}${deployUsername}${REVERT}"
  $echo "\n${GREEN}Run ${BLUE}'cat /home/{deployUsername}/.ssh/id_rsa.pub'${GREEN} to display deployment user's public SSH key${REVERT}\n"
fi

