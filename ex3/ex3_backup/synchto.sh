sshpass -p 'aiTMBcRe9D' ssh root@83.212.111.56 'rm -rf /root/ex3/*'
sshpass -p 'aiTMBcRe9D' scp -r /home/ubuntu/workspace/oslab/ex3/code_folder/* root@83.212.111.56:/root/ex3/  &> /dev/null
echo '--- synch TO end ---'
