$cred = [PSCredential]::new('vagrant-domain@DOMAIN.TEST', (ConvertTo-SecureString -AsPlainText -Force -String 'VagrantPass1'))
New-WSManSession -Uri http://server2019.domain.test:5985/wsman -Authentication NTLM -Credential $cred
