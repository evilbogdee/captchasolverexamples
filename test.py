import time

import undetected_chromedriver as uc

url = 'https://dashboard.capsolver.com/passport/login'

driver = uc.Chrome()
driver.get(url)

time.sleep(5)

driver.quit()
