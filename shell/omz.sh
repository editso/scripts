#! /bin/sh

assert_eq() {
    if [ "$1" != "$2" ]; then
        exit 1
    fi
}

if uname -a | grep -Eqii "Darwin"; then
    if [ ! -f "$(which brew)" ]; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        assert_eq $? 0
    fi
    sudo brew update
    alias pm='brew install'
elif grep -Eqii "Ubuntu" /etc/issue; then
    sudo apt update
    assert_eq $? 0
    alias pm='sudo apt install'
elif grep -Eqii "Manjaro Linux" /etc/issue; then
    sudo pacman -Syyu
    assert_eq $? 0
    alias pm='sudo pacman -S'
elif (grep -Eqii "Centos" /etc/issue || grep -Eqii "centos" /etc/os-release); then
    sudo yum update
    alias pm='sudo yum install'
    assert_eq $? 0
else
    exit 1
fi

pm git zsh

if [ ! -d ${ZSH_CUSTMO:-~/.oh-my-zsh} ]; then
    zsh_install=$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh | sed 's/exec zsh -l/exit/g')
    assert_eq $? 0
    sh -c "$zsh_install"
    assert_eq $? 0
fi

if [ ! -d ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions ]; then
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
    assert_eq $? 0
fi

if [ ! -d ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting ]; then
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
    assert_eq $? 0
fi

sed -r 's/plugins=\((.*)\)/plugins=(\1 zsh-autosuggestions zsh-syntax-highlighting docker sudo)/g' ~/.zshrc > .newzshrc
mv ~/.zshrc ~/.oldzshrc
mv ~/.newzshrc ~/.zshrc
assert_eq $? 0
exec zsh -l

