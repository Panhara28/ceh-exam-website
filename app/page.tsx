import HeroSection from "@/components/hero/HeroSection";
import LearningSection from "@/components/learning/LearnSection";
import ExamPreparationSection from "@/components/exam/ExamPreparationSection";
import SocialMediaSection from "@/components/social-media/SocialMediaSection";
import AboutSection from "@/components/about/AboutSection";
import { Metadata } from "next";

export default function Home() {
  return (
    <>
      {/* Hero Section */}
      <HeroSection />

      {/* Learning Section */}
      <LearningSection />

      {/* Exam Preparation Section */}
      <ExamPreparationSection />

      {/* Social Media Section */}
      <SocialMediaSection />
      {/* About Us Section */}
      <AboutSection />
    </>
  );
}

export const metadata: Metadata = {
  title: "CamShield | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
  openGraph: {
    images: ["/cover.png"],
  },
};
