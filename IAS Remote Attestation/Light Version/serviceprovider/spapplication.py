import requests

sigrl_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/sigrl/00000689"
attestation_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/report"
par_dic = {"isvEnclaveQuote": '\x00', "pseManifest":'\x00', "nounce":'\x00'}


#----------< Function used for configure POST body >--------------------
def encode_attesbody(mode, par_dic):
    
    request_body_json = {}
    if mode == "QUOTE" or mode == "LINKABLE":
        request_body_json["isvEnclaveQuote"] = par_dic["isvEnclaveQuote"]
        
    if mode == "PSE":
        request_body_json["isvEnclaveQuote"] = par_dic["isvEnclaveQuote"]
        request_body_json["pseManifest"] = par_dic["pseManifest"]
        
    if mode == "NONCE":
        request_body_json["isvEnclaveQuote"] = par_dic["isvEnclaveQuote"]
        request_body_json["nonce"] = par_dic["nonce"]
        
    return request_body_json
    

        
        
if __name__ == "__main__":
    
    # Retrive SigRl from IAS
    s = requests.Session()
    r = s.get(sigrl_url, cert=('./certification/client.crt', './certification/client.key'))
    
    print(r.status_code)

    # Make Registration on IAS
    par_dic["isvEnclaveQuote"] = "AQAAAFkGAAAEAAAAAAAAAEUwRDY0NEIyRjEzNkZFMEELEwQq/6W1TdSjsjS7xN2uAgL///8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAHAAAAAAAAANyvxoD+p/f4/m+yw7Fex+Zl6WyvU3C/tSZGS42F91WzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD95ijVpFA6r9ROpfcXp3smR41DSRSkuE+3D8oJVb/WOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMqAIAAAN0Yxi+lWLjMn/MctcZHS8g7c7XGqr+x6xIrdcLHlIGD33EoogXTiJMi8fLqKVpXa27SZ2bc8XUZW2Zok0MO3CkyPPiDrqgMTcx+HNLlOs4RKWFvn3Nu5x0NZZyPDsGbdhTHCiRCwqiVS44/tJjXXz5SKEdgMoGEbmoBRpOw6feoMZ/7+tl74ZO8iM4zHNPspeCo5JAQzKVtxk19gKSTIP9yte+lfb6IaQdRC2xjRGo6Cbn6lisPiqfVWQVUUQzRhq9mmrz2Y3q0yNEWZqkO96ugoUosuXMRnA1aZEG3NMHVBqqQ/31bY4V5MR7JtAZ1ROe+DdCLYhO1SsSvP/Z05sgwr5nxGIL2OONPPOKWSTUDnZXcSXBkqK0tcCPaHjaZPG04iVyTweCvxV9V2gBAACEnMt0hAhgiildiW1koLiRdiZWww9syKVXCDdaU2vTBYGcxO4ANr038njGRR7XLSZENUo62aEWXk+moFKZEfTvdl37WJo0U0W/2RL8KlTi/q80mbP99JSSWw6uW83awHDyX8u00UP2s2HRVCneHnSJdu9LGDLEsePw+oeDABHQzN0MZs39/go5FCBrAXQI28p45B6y0IrV6LJuH2/0l7DGrwFZdBnNmb+JU3eUO64AMeMSXfFXRCjdrmjOZ6PeBCeRo0XjaxKYL4LWmTR3nZALVUj8e9KIoyKdUCKiC5Rqnnjqj9QcagSRevFbIRzFARHEnYi4NsiqkdjgK4JX3NJNBhU3fvgmpWIpcNadgAzsuTBU1aKy8HWyoFdFhxea95MRKVHAwjzAktSv++ULeczxzrWqMoPz8l2dVSOkc8Um23KNecCVQ0vLkwfAry3Rzbl7rXlKLZXMWqF3rh2Ep7eM970nTxMahzfBORZ2XW3q+yPVV7xT5fjw"
    request_body_string = str(encode_attesbody("QUOTE", par_dic))
    attes_s = requests.Session()
    attes_r = attes_s.post(url = attestation_url, data = request_body_string, cert = ('./certification/client.crt', './certification/client.key'))

    print attes_r.status_code
        
        
    











