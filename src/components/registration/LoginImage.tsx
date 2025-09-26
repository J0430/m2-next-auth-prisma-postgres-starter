'use client';
import Image from "next/image";

export default function LoginImage() {
  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
 <Image
        src="https://res.cloudinary.com/dugudxkyu/image/upload/v1676643038/7fbac6523f58c558f3f2329469aa5594_hmabe1.jpg" // update to your asset
        alt="Login illustration"
        fill
        sizes="(min-width: 860px) 40vw, 0vw"
        style={{ objectFit: 'cover' }}
        priority
      />
    </div>
  );
}
