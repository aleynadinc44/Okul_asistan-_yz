import os
from dotenv import load_dotenv
from google import genai

# .env dosyasındaki anahtarı yükle
load_dotenv()

# API anahtarını al
API_KEY = os.getenv("GEMINI_API_KEY")

try:
    # Gemini istemcisini başlat
    client = genai.Client(api_key=API_KEY)
    
    # Basit bir prompt tanımla
    prompt = "Bir öğrenci asistanı için 5 saniyelik motivasyon cümlesi oluştur."
    
    # Gemini API'sini çağır
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt
    )
    
    # Cevabı yazdır
    print(f"Gemini Cevabı: {response.text}")

except Exception as e:
    print(f"Hata oluştu: {e}")