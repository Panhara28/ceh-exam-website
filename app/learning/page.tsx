import LearningSection from "@/components/learning/LearnSection";
import { Metadata } from "next";

export default function LearningPage() {
  return (
    <>
      <LearningSection />
    </>
  );
}

export const metadata: Metadata = {
  title: "Learning | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
};
