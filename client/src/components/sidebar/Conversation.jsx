import React from "react";
import useConversation from "../../zustand/useConversation";
import { useSocketContext } from "../../context/SocketContext";

const Conversation = ({ conversation, emoji, lastIdx }) => {
  const { selectedConversation, setSelectedConversation } = useConversation();

  const isSlected = selectedConversation?._id === conversation._id;
  const { onlineUsers } = useSocketContext();

  const isOnline = onlineUsers.includes(conversation._id)



  return (
    <>
      <div className={`flex gap-2 items-center hover:bg-sky-500 rounded p-2 py-1 cursor-pointer
         ${isSlected ? "bg-sky-500" : ""}`}
         onClick={() => setSelectedConversation(conversation)}
         >
        <div className={`avatar ${isOnline ? "online" : ""}`}>
          <div className="w-12 rounded-full">
            <img src={conversation.profilePic} alt="user avatar" />
          </div>
        </div>

        <div className="flex flex-col flex-1">
          <div className="flex gap-3 justify-between">
            <p className="font-bold text-gray-200">{conversation.fullName}</p>
            <span className="text-xl">{emoji}</span>
          </div>
        </div>
      </div>

      {!lastIdx && <div className="divider my-0 py-0 h-1" />}
    </>
  );
};

export default Conversation;

// import React from "react";

// const Conversation = () => {
//   return (
//     <div>
//       <div className="flex gap-2 items-center hover:bg-sky-500 rounded p-2 py-1 cursor-pointer">
//         <div className="avatar online">
//           <div className="w-12 rounded-full">
//             <img
//               src="https://cdn1.iconfinder.com/data/icons/user-pictures/101/malecostume-512.png"
//               alt="user avatar"
//             />
//           </div>
//         </div>

//         <div className="flex flex-col flex-1">
//             <div className="flex gap-3 justify-between">
//                 <p className="font-bold text-gray-200">John Duo</p>
//                 <span className="text-xl">🤠</span>
//             </div>
//         </div>
//       </div>

//       <div className="divider my-0 py-0 h-1"/>
//     </div>
//   );
// };

// export default Conversation;
