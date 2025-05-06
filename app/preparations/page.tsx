import ExamPreparationSection from "@/components/exam/ExamPreparationSection";
import { Metadata } from "next";

export default function PreperationPage() {
  return (
    <>
      <ExamPreparationSection />
    </>
  );
}

export const metadata: Metadata = {
  title: "Pre-Exam | Learn. Secure. Protect.",
  description:
    "your trusted cybersecurity learning platform in Cambodia. We empower individuals and organizations with practical knowledge, training, and tools to defend against digital threats. Explore hands-on tutorials, up-to-date cybersecurity news, and expert guidance to stay secure in an ever-evolving digital world.",
};
